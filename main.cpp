#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <pthread.h>
#include <map>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <iostream>

// json: https://github.com/zserge/jsmn

#define dws_assert(cond, format, ...) if((cond)) throw std::runtime_error(xsnprintf(128, format, __VA_ARGS__));

class ServerSocket;
class Connection;
class ConnectionListener;
class WebServer;

typedef std::vector<Connection*> Connections;
typedef std::map<std::string, std::string> Params;
typedef std::vector<char> ByteBuffer;

ByteBuffer vxsnprintf(size_t maxlen, const char* format, ...) {
    std::vector<char> buffer(maxlen);
    va_list args;
    va_start(args, format);
    vsnprintf(buffer.data(), maxlen, format, args);
    va_end(args);
    return buffer;
}

std::string xsnprintf(size_t maxlen, const char* format, ...) {
    va_list args;
    va_start(args, format);
    std::vector<char> buffer = vxsnprintf(maxlen, format, args);
    va_end(args);
    return std::string(buffer.data());
}

std::vector<std::string> splitString(const std::string& string, char delim) {
    std::stringstream stream(string);
    std::string token;
    std::vector<std::string> tokens;
    while (getline(stream, token, delim))
        tokens.push_back(token);
    return tokens;
}

template <typename K, typename V>
class CreateMap {
private:
    std::map<K, V> map;
public:
    CreateMap(const K& key, const V& val) {
        map[key] = val;
    }

    CreateMap<K, V>& operator()(const K& key, const V& val) {
        map[key] = val;
        return *this;
    }

    operator std::map<K, V>() {
        return map;
    }
};

template<typename T>
class Ptr {
public:
    Ptr(T* t = 0) : t(t) {}
    ~Ptr() { if (t) delete t; }
	T* operator->() { return t ? t : throw std::runtime_error("pointer is null"); }
private:
	T* t;
};

class BinaryStreamBuffer : public std::streambuf {
public:
    BinaryStreamBuffer() :
            buffer(1 << 12) {
        setp(buffer.data(), buffer.data() + buffer.size());
    }

    virtual ~BinaryStreamBuffer() {
    }

    virtual int_type overflow(int_type c = traits_type::eof()) {
        size_t pos = buffer.size();
        buffer.resize(buffer.size() << 1);
        setp(buffer.data(), buffer.data() + buffer.size());
        pbump(pos);
        *pptr() = c;
        pbump(1);
        return traits_type::not_eof(c);
    }

    std::vector<char> buffer;
};

class IoHandler {
public:
    virtual void handleRead() {}

    virtual void handleWrite() {}
};

class Io {
public:
    typedef std::map<int, IoHandler*> HandlersMap;

    Io() {}

    void wait() {
        int nfds = 0;

        fd_set read_fds;
        fd_set write_fds;

        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);

        for (HandlersMap::iterator handlerIt = _readHandlers.begin(); handlerIt != _readHandlers.end(); ++handlerIt) {
            FD_SET(handlerIt->first, &read_fds);
            nfds = std::max(nfds, handlerIt->first);
        }
        for (HandlersMap::iterator handlerIt = _writeHandlers.begin(); handlerIt != _writeHandlers.end(); ++handlerIt) {
            FD_SET(handlerIt->first, &write_fds);
            nfds = std::max(nfds, handlerIt->first);
        }

        if (select(nfds + 1, &read_fds, &write_fds, NULL, NULL) <= 0)
            return;

        for (int i = 0; i <= nfds; ++i) {
            if (FD_ISSET(i, &read_fds)) {
                for (HandlersMap::iterator handlerIt = _readHandlers.begin();
                     handlerIt != _readHandlers.end(); ++handlerIt) {
                    if (handlerIt->first != i) continue;
                    handlerIt->second->handleRead();
                }
            } else if (FD_ISSET(i, &write_fds)) {
                for (HandlersMap::iterator handlerIt = _writeHandlers.begin();
                     handlerIt != _writeHandlers.end(); ++handlerIt) {
                    if (handlerIt->first != i) continue;
                    handlerIt->second->handleWrite();
                }
            }
        }
    }

    Io* addHandlers(int fd, IoHandler* readHandler, IoHandler* writeHandler) {
        if (readHandler)
            _readHandlers.insert(std::make_pair(fd, readHandler));
        if (writeHandler)
            _writeHandlers.insert(std::make_pair(fd, writeHandler));
        return this;
    }

    Io* removeHandlers(int fd) {
        HandlersMap::iterator readHandlerIt = _readHandlers.find(fd);
        if (readHandlerIt != _readHandlers.end()) {
            _readHandlers.erase(readHandlerIt);
        }
        HandlersMap::iterator writeHandlerIt = _writeHandlers.find(fd);
        if (writeHandlerIt != _writeHandlers.end()) {
            _writeHandlers.erase(writeHandlerIt);
        }
        return this;
    }

private:
    HandlersMap _readHandlers;
    HandlersMap _writeHandlers;
};


class ConnectionHandler {
public:
    virtual ~ConnectionHandler() {
    }

    virtual bool handleRead(const std::vector<char>& data, Connection* connection) = 0;
};

class Connection : public IoHandler {
public:
    Connection(int fd, ConnectionHandler* connectionHandler, ConnectionListener* connectionListener)
            : fd(fd), connectionHandler(connectionHandler), connectionListener(connectionListener) {}

    virtual ~Connection() {
        ::shutdown(fd, SHUT_RDWR);
        close(fd);
    }

    virtual void handleRead();

    bool sendData(const std::vector<char>& data) {
        return sendData(data.data(), data.size());
    }

    bool sendData(const std::string& data) {
        return sendData(data.data(), data.size());
    }

    bool sendData(const char* data, size_t size) {
        int summaryBytesSended = 0;
        do {
            char* ptr = const_cast<char*>(data) + summaryBytesSended;
            size_t balance = size - summaryBytesSended;

            ssize_t bytesSended = send(fd, ptr, balance, MSG_NOSIGNAL);

            summaryBytesSended += bytesSended;
        } while (summaryBytesSended < size);
        return true;
    }

    int fd;
    ConnectionHandler* connectionHandler;
    ConnectionListener* connectionListener;
};

class ConnectionListener: public IoHandler {
public:
    ConnectionListener(uint16_t port, Io* io, ConnectionHandler* connectionHandler)
            : io(io), connectionHandler(connectionHandler) {
        sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (sock < 0) throw std::runtime_error(xsnprintf(64, "create socket error: %s\n", strerror(errno)));

        sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_ANY);

        while (true) {
            address.sin_port = htons(port);

            if (bind(sock, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
                printf("bind socket error: %s\n", strerror(errno));
                port++;
                continue;
            } else {
                printf("bind socket success: %d\n", port);
                printf("http://127.0.0.1:%d\n", port);
                break;
            }
        }

        if (listen(sock, 32) < 0) throw std::runtime_error(xsnprintf(64, "listen socket error: %s\n", strerror(errno)));

        io->addHandlers(sock, this, NULL);
    }

    virtual ~ConnectionListener() {
        for (Connections::iterator it = connections.begin(); it != connections.end(); ++it) {
            delete (*it);
        }
        ::shutdown(sock, SHUT_RDWR);
        close(sock);
    }

    virtual void handleRead() {
        int fd = accept(sock, NULL, NULL);
        Connection* connection = new Connection(fd, connectionHandler, this);
        connections.push_back(connection);
        io->addHandlers(fd, connection, NULL);
    }

    void remoteConnection(Connection* connection) {
        Connections::iterator connectionIt = std::find(connections.begin(), connections.end(), connection);
        if (connectionIt != connections.end()) {
            io->removeHandlers((*connectionIt)->fd);
            delete (*connectionIt);
            connections.erase(connectionIt);
        }
    }

    Io* io;
    int sock;
    ConnectionHandler* connectionHandler;
    Connections connections;
};

void Connection::handleRead() {
    size_t buffer_size = 4096;

    std::vector<char> buffer;
    buffer.resize(buffer_size);

    ssize_t bytesReceived = recv(fd, buffer.data(), buffer.size(), 0);

    if (bytesReceived == 0) {
        ::shutdown(fd, SHUT_RDWR);
        close(fd);
        connectionListener->remoteConnection(this);
    } else if (bytesReceived < buffer_size) {
        if (!connectionHandler->handleRead(buffer, this)) {
            printf("warning: handleRead fail\n");
        }
    } else if (bytesReceived == buffer_size) {
        printf("warning: receive buffer overflow\n");
    } else if (bytesReceived < 0) {
        throw std::runtime_error(xsnprintf(64, "recv error: %s", strerror(errno)));
    }
}

class Pipes : public IoHandler {
public:
    Pipes(Io* io, bool* work) : work(work) {
        if (pipe(pfds) < 0) throw std::runtime_error(xsnprintf(64, "can't create pipes: %s\n", strerror(errno)));

        int flags = 0;

        flags = fcntl(pfds[0], F_GETFL);
        if (flags < 0) throw std::runtime_error(xsnprintf(64, "can't get pipe flags: %s\n", strerror(errno)));

        flags |= O_NONBLOCK;
        if (fcntl(pfds[0], F_SETFL, flags) < 0)
            throw std::runtime_error(xsnprintf(64, "can't set pipe flags: %s\n", strerror(errno)));

        flags = fcntl(pfds[1], F_GETFL);
        if (flags < 0) throw std::runtime_error(xsnprintf(64, "can't get pipe flags: %s\n", strerror(errno)));

        flags |= O_NONBLOCK;
        if (fcntl(pfds[1], F_SETFL, flags) < 0)
            throw std::runtime_error(xsnprintf(64, "can't set pipe flags: %s\n", strerror(errno)));

        io->addHandlers(pfds[0], this, NULL);
    }

    virtual ~Pipes() {
        close(pfds[0]);
        close(pfds[1]);
    }

    bool shutdown() {
        int savedErrno = errno;
        bool result = write(pfds[1], "x", 1) < 0 && errno != EAGAIN;
        errno = savedErrno;
        return result;
    }

    virtual void handleRead() {
        if (work)
            *work = false;
    }

    int pfds[2];
    bool* work;
};

class ServerSocket {
public:
    ServerSocket(uint16_t port, ConnectionHandler* connectionHandler) :
            port(port), connectionHandler(connectionHandler) {
        pthread_create(&thread, NULL, threadBody, this);
    }

    ~ServerSocket() {
        shutdown();
        pthread_join(thread, NULL);
    }

    static void* threadBody(void* userData) {
        ServerSocket* self = static_cast<ServerSocket*>(userData);
        try {
            Io io;
            ConnectionListener connectionListener(self->port, &io, self->connectionHandler);

            bool work = true;
            Pipes pipes(&io, &work);
            self->pipes = &pipes;

            while (work)
                try {
                    io.wait();
                } catch (std::runtime_error const& e) {
                    printf("handleRead error: %s\n", e.what());
                }
        } catch (std::exception const& e) {
            printf("error: %s\n", e.what());
        }
        return NULL;
    }

    ConnectionHandler *getHandler() {
        return connectionHandler;
    }

    void setHandler(ConnectionHandler *connectionHandler) {
        this->connectionHandler = connectionHandler;
    }

    bool shutdown() {
        return pipes->shutdown();
    }

private:
    uint16_t port;
    pthread_t thread;

    ConnectionHandler *connectionHandler;
	Pipes* pipes;
};

struct Request {
    enum Method {
        GET = 0x01,
        POST = 0x02,
        INVALID = 0xFF,
        ALL = GET | POST,
    };

    Request(Method method = INVALID, const std::string& request = "")
            : method(method), request(request) {
    }

    Request(const std::string& methodStr, const std::string& fullRequest) {
        method =
                methodStr == "GET" ? Request::GET :
                methodStr == "POST" ? Request::POST : Request::INVALID;

        std::string resRequest, resParams;
        if (splitTwiceByChar(resRequest, resParams, fullRequest, '?')) {
            this->request = resRequest;

            std::vector<std::string> params;
            splitParams(params, resParams);
            splitParam(this->params, params);
        } else {
            this->request = fullRequest;
        }
    }

    static void splitParams(std::vector<std::string>& params, const std::string& fullParams) {
        std::stringstream paramStream(fullParams);
        std::string token;
        while (getline(paramStream, token, '&'))
            params.push_back(token);
    }

    static bool splitTwiceByChar(std::string& first, std::string& second, const std::string& str, char delim) {
        std::stringstream stream(str);
        std::string token;
        std::vector<std::string> tokens;
        while (getline(stream, token, delim))
            tokens.push_back(token);
        if (tokens.size() < 1 && tokens.size() > 2)
            return false;
        if (tokens.size() >= 1)
            first = tokens.at(0);
        if (tokens.size() >= 2)
            second = tokens.at(1);
        return true;
    }

    static void splitParam(Params& params, const std::vector<std::string>& fullParams) {
        for (std::vector<std::string>::const_iterator it = fullParams.begin(); it != fullParams.end(); ++it) {
            std::string first, second;
            if (splitTwiceByChar(first, second, *it, '='))
                params.insert(std::make_pair(first, second));
        }
    }

    operator bool() const {
        return method != INVALID && !request.empty();
    }

    friend bool operator<(const Request& lhs, const Request& rhs);

    friend std::ostream& operator<<(std::ostream& os, const Request& request);

    Method method;
    std::string request;

    Params params;
};

bool operator<(const Request& lhs, const Request& rhs)
{
//	if (lhs.method < rhs.method)
//		return true;
//	if (rhs.method < lhs.method)
//		return false;
	return lhs.request < rhs.request;
}

std::ostream& operator<<(std::ostream& os, const Request& request) {
    os << "method: " << request.method << ", request: " << request.request;
    if (request.params.empty())
        return os;
    os << ", params: { ";
    for (Params::const_iterator it = request.params.begin(); it != request.params.end(); ++it) {
        os << "[" << it->first << ": " << it->second << "], ";
    }
    os << "}";
    return os;
}

class Response {
public:
    Response(const std::vector<char>& data = std::vector<char>(), bool valid = false)
            : data(data), valid(valid) {
    }

    std::vector<char> data;
    bool valid;
};

class RequestHandler {
public:
    RequestHandler() : _webServer(NULL) {}

    virtual ~RequestHandler() {}

    virtual Response getResponse(const Request& request = Request()) = 0;

    WebServer* getWebServer() {
        return _webServer;
    }

    RequestHandler* setWebServer(WebServer* webServer) {
        _webServer = webServer;
        return this;
    }

protected:
    WebServer* _webServer;
};

class FileHandler : public RequestHandler {
    std::string _fileName;
public:
    FileHandler(const std::string& fileName) :
            _fileName(fileName) {
    }

    virtual ~FileHandler() {
    }

    virtual Response getResponse(const Request& request);
};

class PageHandler : public RequestHandler {
    std::string _page;
public:
    PageHandler(const std::string& page = 0) : _page(page) {}

    virtual ~PageHandler() {}

    virtual Response getResponse(const Request& request) {
        const char* answer_template =
                "HTTP/1.1 200 OK\r\n"
                "Server: ShnaiderServer/2017-01-01\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %d\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
                "%s"
                "\r\n"
        ;

        size_t size = strlen(answer_template) + _page.size() + 1024;
        return Response(vxsnprintf(size, answer_template, _page.size(), _page.c_str()), true);
    }
};

class JsonHandler : public RequestHandler {
    std::string _page;
public:
    JsonHandler(const std::string& page) : _page(page) {}

    virtual ~JsonHandler() {}

    virtual Response getResponse(const Request& request) {
        const char* answer_template =
                "HTTP/1.1 200 OK\r\n"
                "Server: ShnaiderServer/2017-01-01\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %d\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
                "%s"
                "\r\n"
        ;

        size_t len = strlen(answer_template) + _page.size() + 1024;
        return Response(vxsnprintf(len, answer_template, _page.size(), _page.c_str()), true);
    }
};

class FunctionHandler : public RequestHandler {
public:
    typedef Response (* handler_t)(const Params&);

    FunctionHandler(handler_t handler = 0) : handler(handler) {}

    virtual Response getResponse(const Request& request) {
        return handler ? handler(request.params) : Response();
    }

private:
    handler_t handler;
};

class HttpResponseBuilder {
public:

    enum Protocol {
        Http,
        Protocol_Count,
    };

    enum ErrorCode {
        OK_200 = 200,
        NotFound_404 = 404,
        NotImplemented_501 = 501,
    };

    enum ConnectionType {
        KeepAlive, Close,
    };

    enum ContentType {
        ContentType_Count,
    };

    typedef std::map<ErrorCode, const char*> ErrorCodeCommentMap;
    static ErrorCodeCommentMap errorCodeCommentMap;

    typedef std::map<std::string, std::string> ExtensionToContentType;
    static ExtensionToContentType extensionToContentType;

    HttpResponseBuilder()
            : protocol(Http)
            , protocolVersionMajor(1)
            , protocolVersionMinor(1)
            , errorCode(OK_200)
            , serverName("ShnaiderServer/2017-01-01")
            , contentType("text/html")
            , connectionType(KeepAlive)
            , stream(&buffer)
    {}

    HttpResponseBuilder& setProtocol(Protocol protocol) {
        this->protocol = protocol;
        return *this;
    }

    HttpResponseBuilder& setProtocolVersion(int major, int minor) {
        this->protocolVersionMajor = major;
        this->protocolVersionMinor = minor;
        return *this;
    }

    HttpResponseBuilder& setErrorCode(ErrorCode errorCode) {
        this->errorCode = errorCode;
        return *this;
    }

    HttpResponseBuilder& setServerName(const std::string& serverName) {
        this->serverName = serverName;
        return *this;
    }

    HttpResponseBuilder& setContentType(const std::string& contentType) {
        this->contentType = contentType;
        return *this;
    }

    HttpResponseBuilder& setContentTypeByFileName(const std::string& fileName) {
        contentType = getContentTypeForExtension(getExtension(fileName));
        return *this;
    }

    HttpResponseBuilder& setConnection(ConnectionType connectionType) {
        this->connectionType = connectionType;
        return *this;
    }

    HttpResponseBuilder& build(const ByteBuffer& content = ByteBuffer()) {
        stream << (protocol == Http ? "HTTP" : "") << "/" << protocolVersionMajor << "." << protocolVersionMinor << " "
               << errorCode << " " << errorCodeCommentMap[errorCode] << "\r\n";

        stream << "Server: " << serverName << "\r\n";
        stream << "Content-Type: " << contentType << "\r\n";
        stream << "Content-Length: " << content.size() << "\r\n";
        stream << "Connection: " << (connectionType == KeepAlive ? "keep-alive" : "close") << "\r\n";

        stream << "\r\n";
        stream.write(content.data(), content.size());
        stream << "\r\n";

//        std::cout << buffer.buffer.data() << std::endl;
        return *this;
    }

    void send(Connection* connection) {
        connection->sendData(buffer.buffer);
    }

    static std::string getContentTypeForExtension(const std::string& extension) {
        std::map<std::string, std::string>::const_iterator mimeTypeIt = extensionToContentType.find(extension);
        return mimeTypeIt == extensionToContentType.end() ? "text/html" : mimeTypeIt->second;
    }

    static std::string getExtension(const std::string& request) {
        std::vector<std::string> tokens = splitString(request, '.');
        if (tokens.empty())
            throw std::runtime_error("tokens are empty");
        return tokens.back();
    }

    Protocol protocol;
    int protocolVersionMajor;
    int protocolVersionMinor;
    ErrorCode errorCode;
    std::string serverName;
    std::string contentType;
    ConnectionType connectionType;

    BinaryStreamBuffer buffer;
    std::ostream stream;
};

HttpResponseBuilder::ErrorCodeCommentMap HttpResponseBuilder::errorCodeCommentMap =
    CreateMap<HttpResponseBuilder::ErrorCode, const char*>
        (HttpResponseBuilder::OK_200, "Ok")
        (HttpResponseBuilder::NotFound_404, "Not Found")
        (HttpResponseBuilder::NotImplemented_501, "Not Implemented")
;

HttpResponseBuilder::ExtensionToContentType HttpResponseBuilder::extensionToContentType =
    CreateMap<std::string, std::string>
        ("html"    , "text/html"          )
        ("js"      , "text/javascript"    )
        ("css"     , "text/css"           )
        ("ico"     , "image/x-icon"       )
        ("png"     , "image/png"          )
;

class WebServer : public ConnectionHandler {
public:
    typedef std::map<Request, RequestHandler*> RequestMap;

    enum ErrorCode {
        NotFound_404,

        NotImplemented_501,
    };

    static std::map<ErrorCode, const char*> errors;

    WebServer(uint16_t port = 8080) :
            _socket(new ServerSocket(port, this)) {
        _extToFileType.insert(std::make_pair("html", "text/html"));
        _extToFileType.insert(std::make_pair("js", "text/javascript"));
        _extToFileType.insert(std::make_pair("css", "text/css"));
        _extToFileType.insert(std::make_pair("ico", "image/x-icon"));
        _extToFileType.insert(std::make_pair("png", "image/png"));
    }

    ~WebServer() {
        for (RequestMap::iterator requestIt = _requestHandlers.begin();
             requestIt != _requestHandlers.end(); ++requestIt) {
            delete requestIt->second;
        }
    }

    WebServer *setDirectory(const std::string &filesDirectory) {
        _filesDirectory = filesDirectory;
        return this;
    }

    const std::string& getDirectory() const {
        return _filesDirectory;
    }

    WebServer *addRequest(const Request &request, RequestHandler *requestHandler) {
        requestHandler->setWebServer(this);
        _requestHandlers.insert(std::make_pair(request, requestHandler));
        return this;
    }

    bool handleRead(const std::vector<char>& data, Connection* connection) {
        if (data.empty())
            return false;

        std::stringstream ss(data.data());

        std::string methodStr;
        std::string requestStr;

        ss >> methodStr;
        ss >> requestStr;

        printf("%s: %s\n", methodStr.c_str(), requestStr.c_str());
        const Request& request = Request(methodStr, requestStr);

        if (checkAndResponseFile(request, connection))
            return true;

        std::cout << request << std::endl;

        RequestMap::iterator it = _requestHandlers.find(request);
        if (it == _requestHandlers.end()/* && (request.method & it->first.method)*/) {
            HttpResponseBuilder().
                    setErrorCode(HttpResponseBuilder::NotImplemented_501).
                    build().
                    send(connection);
            return false;
        }

        Response response = it->second->getResponse(request);

        return response.valid ? connection->sendData(response.data) : false;
    }

    bool checkAndResponseFile(const Request& request, Connection* connection) {
        if (getDirectory().empty())
            return false;

        FileHandler fileHandler(request.request);
        fileHandler.setWebServer(this);
        Response response = fileHandler.getResponse(request);
        if (response.valid) {
            connection->sendData(response.data);
            return true;
        }
        return false;
    }

    std::string getMimeTypeForExtension(const std::string &extension) const {
        std::map<std::string, std::string>::const_iterator mimeTypeIt = _extToFileType.find(extension);
        return mimeTypeIt == _extToFileType.end() ? "text/html" : mimeTypeIt->second;
    }

    std::string getExtension(const std::string &request) const {
        std::stringstream stream;
        std::string token;
        stream << request;
        while(getline(stream, token, '.'));
        return token;
    }

    bool shutdown() {
        return _socket->shutdown();
    }

private:
    Ptr<ServerSocket> _socket;
    RequestMap _requestHandlers;
    std::string _filesDirectory;

	std::map<std::string, std::string> _extToFileType;
};

std::map<WebServer::ErrorCode, const char*> WebServer::errors = CreateMap<WebServer::ErrorCode, const char*>
	(WebServer::NotFound_404,
		"HTTP/1.1 404 OK\r\n"
		"Server: ShnaiderServer/2017-01-01\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: 0\r\n"
		"Connection: keep-alive\r\n"
		"\r\n"
		"\r\n")
	(WebServer::NotImplemented_501,
		"HTTP/1.1 501 OK\r\n"
		"Server: ShnaiderServer/2017-01-01\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: 0\r\n"
		"Connection: keep-alive\r\n"
		"\r\n"
		"\r\n"
	);


Response FileHandler::getResponse(const Request& request) {
    const char* answer_template =
        "HTTP/1.1 200 OK\r\n"
        "Server: ShnaiderServer/2017-01-01\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";

    std::vector<char> response;

    std::string sep;
    if (_fileName.at(0) != '/')
        sep = "/";

    std::string filename = _webServer->getDirectory() + sep + _fileName;

    struct stat path;
    stat(filename.c_str(), &path);
    if (!S_ISREG(path.st_mode)) {
        return Response();
    }

    FILE* file = fopen(filename.c_str(), "rb");

    if (file) {
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        rewind(file);

        std::string extension = _webServer->getExtension(_fileName);
        std::string mimeType = _webServer->getMimeTypeForExtension(extension);

        response.resize(strlen(answer_template) + size + 1024);
        snprintf(response.data(), response.size(), answer_template, mimeType.c_str(), size);

        char* ptr = response.data() + strlen(response.data());

        size_t bytesRead = fread(ptr, 1, static_cast<size_t>(size), file);

        ptr += bytesRead;

        memcpy(ptr, "\r\n", 2);

        if (bytesRead != size) {
            printf("warning: read size not match\n");
        }

        fclose(file);

        return Response(response, true);
    } else {
        return Response();
    }
}

pthread_mutex_t mutex;
pthread_cond_t cond;

bool programWork = true;

void signal_handler(int) {
    pthread_mutex_lock(&mutex);
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);
}

Response stopProgramRequest(const Params&) {
    programWork = false;
    signal_handler(0);
    return Response();
}

int main() {
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&cond, NULL);

    while (programWork) {
        signal(SIGINT, signal_handler);

        Ptr<WebServer> ws((new WebServer(9001))
            ->setDirectory("static")
            ->addRequest(Request(Request::ALL, "/"            ), new FileHandler("index.html"))
            ->addRequest(Request(Request::ALL, "/test_json"   ), new JsonHandler("{\"test\": 42}"))
            ->addRequest(Request(Request::ALL, "/quit"        ), new FunctionHandler(stopProgramRequest))
            ->addRequest(Request(Request::ALL, "/update_log"  ), new JsonHandler("{\"log\": \"Log text\"}"))
        );

        pthread_mutex_lock(&mutex);
        pthread_cond_wait(&cond, &mutex);
        pthread_mutex_unlock(&mutex);
    }
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);
    return 0;
}


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

// json: https://github.com/zserge/jsmn

template<typename T>
class Ptr {
public:
    Ptr(T* t = 0) : t(t) {}
    ~Ptr() { if (t) delete t; }
	T* operator->() { return t ? t : throw std::runtime_error("pointer is null"); }
private:
	T* t;
};

std::vector<char> vxsnprintf(size_t maxlen, const char* format, ...) {
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

//#define dws_assert(cond, format, ...)

class ServerSocket;

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

		for (int i = 0; i <= nfds; ++i)
		{
			if (FD_ISSET(i, &read_fds))
			{
				for (HandlersMap::iterator handlerIt = _readHandlers.begin(); handlerIt != _readHandlers.end(); ++handlerIt)
				{
					if (handlerIt->first != i) continue;
					handlerIt->second->handleRead();
				}
			}
			else if(FD_ISSET(i, &write_fds))
			{
				for (HandlersMap::iterator handlerIt = _writeHandlers.begin(); handlerIt != _writeHandlers.end(); ++handlerIt)
				{
					if (handlerIt->first != i) continue;
					handlerIt->second->handleWrite();
				}
			}
		}
	}

	Io* addHandlers(int fd, IoHandler* readHandler, IoHandler* writeHandler)
	{
		if (readHandler)
			_readHandlers.insert(std::make_pair(fd, readHandler));
		if (writeHandler)
			_writeHandlers.insert(std::make_pair(fd, writeHandler));
		return this;
	}

	Io* removeHandlers(int fd) {
		HandlersMap::iterator readHandlerIt = _readHandlers.find(fd);
		if(readHandlerIt != _readHandlers.end())
		{
			delete  readHandlerIt->second;
			_readHandlers.erase(readHandlerIt);
		}
		HandlersMap::iterator writeHandlerIt = _writeHandlers.find(fd);
		if(writeHandlerIt != _writeHandlers.end())
		{
			delete writeHandlerIt->second;
			_writeHandlers.erase(writeHandlerIt);
		}
		return this;
	}

private:
	HandlersMap _readHandlers;
	HandlersMap _writeHandlers;
};

class Connection;

class ConnectionHandler {
public:
	virtual ~ConnectionHandler() {
	}

	virtual bool handleRead(const std::vector<char>& data, Connection* connection) = 0;
};

class Connection: public IoHandler {
public:
	Connection(int fd, ConnectionHandler* connectionHandler, Io* io) : fd(fd), connectionHandler(connectionHandler), io(io)
	{}

	virtual ~Connection()
	{
		::shutdown(fd, SHUT_RDWR);
		close(fd);
	}

	virtual void handleRead()
	{
		size_t buffer_size = 4096;

		std::vector<char> buffer;
		buffer.resize(buffer_size);

		ssize_t bytesReceived = recv(fd, buffer.data(), buffer.size(), 0);

		if (bytesReceived == 0)
		{
			::shutdown(fd, SHUT_RDWR);
			close(fd);

			io->removeHandlers(fd);
		}
		else if (bytesReceived < buffer_size)
		{
			bool handleResult = connectionHandler->handleRead(buffer, this);
			if (!handleResult)
			{
				printf("warning: can't handleRead result\n");
			}
		}
		else if (bytesReceived == buffer_size)
		{
			printf("warning: receive buffer overflow\n");
		}
		else if (bytesReceived < 0)
		{
			throw std::runtime_error(xsnprintf(64, "recv error: %s", strerror(errno)));
		}
	}

	bool sendData(const std::vector<char> &data) {
		return sendData(data.data(), data.size());
	}

	bool sendData(const std::string &data) {
		return sendData(data.data(), data.size());
	}

	bool sendData(const char *data, size_t size) {
		int summaryBytesSended = 0;
		do {
			char *ptr = const_cast<char *>(data) + summaryBytesSended;
			size_t balance = size - summaryBytesSended;

			ssize_t bytesSended = send(fd, ptr, balance, MSG_NOSIGNAL);

			summaryBytesSended += bytesSended;
		} while (summaryBytesSended < size);
		return true;
	}

	int fd;
	ConnectionHandler* connectionHandler;
	Io* io;
};

class ConnectionListener: public IoHandler {
public:
	ConnectionListener(uint16_t port, Io* io, ConnectionHandler* connectionHandler) : io(io), connectionHandler(connectionHandler)
	{
		sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
		if (sock < 0) throw std::runtime_error(xsnprintf(64, "create socket error: %s\n", strerror(errno)));

		sockaddr_in address;
		memset(&address, 0, sizeof(address));
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = htonl(INADDR_ANY);

		while (true) {
			address.sin_port = htons(port);

			int bindResult = bind(sock, reinterpret_cast<sockaddr *>(&address), sizeof(address));
			if (bindResult < 0) {
				printf("bind socket error: %s\n", strerror(errno));
				port++;
				continue;
			} else {
				printf("bind socket success: %d\n", port);
				printf("http://127.0.0.1:%d\n", port);
				break;
			}
		}

		int listenResult = listen(sock, 32);
		if (listenResult < 0) throw std::runtime_error(xsnprintf(64, "listen socket error: %s\n", strerror(errno)));

		io->addHandlers(sock, this, NULL);
	}

	virtual ~ConnectionListener()
	{
        ::shutdown(sock, SHUT_RDWR);
        close(sock);
	}

	virtual void handleRead()
	{
		int fd = accept(sock, NULL, NULL);
		io->addHandlers(fd, new Connection(fd, connectionHandler, io), NULL);
	}

	Io* io;
	int sock;
	ConnectionHandler* connectionHandler;
};

class Pipes: public IoHandler {
public:
	Pipes(Io* io, bool* work) : work(work)
	{
		if (pipe(pfds) < 0) throw std::runtime_error(xsnprintf(64, "can't create pipes: %s\n", strerror(errno)));

		int flags = 0;

		flags = fcntl(pfds[0], F_GETFL);
		if (flags < 0) throw std::runtime_error(xsnprintf(64, "can't get pipe flags: %s\n", strerror(errno)));

		flags |= O_NONBLOCK;
		if (fcntl(pfds[0], F_SETFL, flags) < 0) throw std::runtime_error(xsnprintf(64, "can't set pipe flags: %s\n", strerror(errno)));

		flags = fcntl(pfds[1], F_GETFL);
		if (flags < 0) throw std::runtime_error(xsnprintf(64, "can't get pipe flags: %s\n", strerror(errno)));

		flags |= O_NONBLOCK;
		if (fcntl(pfds[1], F_SETFL, flags) < 0) throw std::runtime_error(xsnprintf(64, "can't set pipe flags: %s\n", strerror(errno)));

		io->addHandlers(pfds[0], this, NULL);
	}

	virtual ~Pipes()
	{
        close(pfds[0]);
        close(pfds[1]);
	}

	bool shutdown()
	{
		int savedErrno = errno;
		bool result = write(pfds[1], "x", 1) < 0 && errno != EAGAIN;
		errno = savedErrno;
		return result;
	}

	virtual void handleRead()
	{
		if (work)
			*work = false;
	}

	int pfds[2];
	bool *work;
};

class ServerSocket {
public:
    ServerSocket(uint16_t port, ConnectionHandler* connectionHandler) :
			port(port), connectionHandler(connectionHandler)
	{
        pthread_create(&thread, NULL, threadBody, this);
    }

    ~ServerSocket() {
        shutdown();
        pthread_join(thread, NULL);
    }

    static void *threadBody(void *userData) {
        ServerSocket *self = static_cast<ServerSocket *>(userData);
		try
		{
			Io io;
			ConnectionListener connectionListener(self->port, &io, self->connectionHandler);

			bool work = true;
			Pipes pipes(&io, &work);
			self->pipes = &pipes;

			while (work)
				try
				{
					io.wait();
				}
				catch (std::runtime_error const& e)
				{
					printf("handleRead error: %s\n", e.what());
				}
		}
		catch (std::exception const& e)
		{
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

class Response {
public:
	Response(const std::vector<char>& data = std::vector<char>(), bool valid = false) : data(data), valid(valid) {}

	std::vector<char> data;
	bool valid;
};

class WebServer;

class RequestHandler {
public:
	RequestHandler() : _webServer(NULL) {}
	virtual ~RequestHandler() {}

	virtual Response getResponse() = 0;

	WebServer *getWebServer() {
		return _webServer;
	}

	RequestHandler *setWebServer(WebServer *webServer) {
		_webServer = webServer;
		return this;
	}

protected:
	WebServer *_webServer;
};

class FileHandler : public RequestHandler {
	std::string _fileName;
public:
	FileHandler(const std::string &fileName) :
			_fileName(fileName) {
	}

	virtual ~FileHandler() {
	}

	virtual Response getResponse();
};

class PageHandler : public RequestHandler {
	std::string _page;
public:
	PageHandler(const std::string &page = 0) : _page(page) {}
	virtual ~PageHandler() {}

	virtual Response getResponse() {
		const char *answer_template =
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

	virtual Response getResponse() {
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
	typedef Response (*handler_t)();

	FunctionHandler(handler_t handler = 0) : handler(handler) {}

	virtual Response getResponse() {
		return handler ? handler() : Response();
	}

private:
	handler_t handler;
};

class WebServer : public ConnectionHandler {
public:
    typedef std::map<std::string, RequestHandler*> RequestMap;

	WebServer(uint16_t port = 8080) :
			_socket(new ServerSocket(port, this))
	{
		_extToFileType.insert(std::make_pair("html", "text/html"));
		_extToFileType.insert(std::make_pair("js", "text/javascript"));
		_extToFileType.insert(std::make_pair("ico", "image/x-icon"));
		_extToFileType.insert(std::make_pair("png", "image/png"));
	}

    ~WebServer() {
		for (RequestMap::iterator requestIt = _requestHandlers.begin(); requestIt != _requestHandlers.end(); ++requestIt) {
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

    WebServer *addRequest(const std::string &requestString, RequestHandler *requestHandler) {
        requestHandler->setWebServer(this);
        _requestHandlers.insert(std::make_pair(requestString, requestHandler));
        return this;
    }

    bool handleRead(const std::vector<char>& data, Connection* connection)
	{
        if (data.empty())
            return false;

        std::stringstream ss(data.data());

        std::string method;
        std::string request;

        ss >> method;
        ss >> request;

        if (checkAndResponseFile(request, connection))
            return true;

        RequestMap::iterator it = _requestHandlers.find(request);
        if (it == _requestHandlers.end())
            return false;

		Response response = it->second->getResponse();

		return response.valid ? connection->sendData(response.data) : false;
    }

    bool checkAndResponseFile(const std::string &request, Connection *connection) {
        if (getDirectory().empty())
            return false;

        FileHandler fileHandler(request);
        fileHandler.setWebServer(this);
        Response response = fileHandler.getResponse();
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

Response FileHandler::getResponse() {
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

Response stopProgramRequest() {
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
            ->addRequest("/", new FileHandler("index.html"))
            ->addRequest("/test_json", new JsonHandler("{\"test\": 42}"))
            ->addRequest("/quit", new FunctionHandler(stopProgramRequest))
            ->addRequest("/update_log", new JsonHandler("{\"log\": \"Log text\"}"))
        );

        pthread_mutex_lock(&mutex);
        pthread_cond_wait(&cond, &mutex);
        pthread_mutex_unlock(&mutex);
    }
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);
    return 0;
}


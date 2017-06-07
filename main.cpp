#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
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
	T *t;

public:
	Ptr(T *t = 0) :
			t(t) {
	}

	~Ptr() {
		if (t)
			delete t;
	}

	T *operator->() {
		return t ? t : throw std::runtime_error("pointer is null");
	}

	Ptr(const Ptr& other) {
		*this = other;
	}

	Ptr& operator=(const Ptr& other) {
		if (this != &other) {
			std::swap(t, const_cast<Ptr&>(other).t); // TODO const_cast bad
		}
		return *this;
	}
};

class ServerSocket {
public:
    class Connection {
    public:
        Connection(int fd) :
                _fd(fd) {
        }

        operator int() const {
            return _fd;
        }

        int _fd;
    };

    typedef std::vector<Connection> Connections;

	class Handler {
	public:
		virtual ~Handler() {
		}

		virtual bool handle(const std::vector<char> &data, size_t bytesReceived, ServerSocket *socket,
							const Connection &conn) = 0;
	};

	ServerSocket(uint16_t port = 8080) :
			_port(port) {
		pthread_create(&_thread, NULL, threadBody, this);
	}

	~ServerSocket() {
		shutdown();
		printf("before join\n");
		pthread_join(_thread, NULL);
		printf("after join\n");
	}

    static void *threadBody(void *userData) {
        ServerSocket *self = static_cast<ServerSocket *>(userData);

        int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (sock < 0) {
            printf("create socket error: %s\n", strerror(errno));
            return NULL;
        }

        sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_ANY);

        uint16_t port = self->_port;

        while (true) {
            address.sin_port = htons(port);

            int bindResult = bind(sock, reinterpret_cast<sockaddr *>(&address), sizeof(address));
            if (bindResult < 0) {
                printf("bind socket error: %s\n", strerror(errno));
                port++;
                continue;
            } else {
                printf("bind socket success: %d\n", port);
                break;
            }
        }

        int listenResult = listen(sock, 32);
        if (listenResult < 0) {
            printf("listen socket error: %s\n", strerror(errno));
            return NULL;
        }

        Connections connections;

        fd_set read_fds;
        fd_set write_fds;

        if (pipe(self->_pfds) < 0) {
            printf("can't create pipes: %s\n", strerror(errno));
            return NULL;
        }

        int flags = 0;
        flags = fcntl(self->_pfds[0], F_GETFL);
        if (flags < 0) {
            printf("can't get pipe flags: %s\n", strerror(errno));
            return NULL;
        }
        flags |= O_NONBLOCK;
        if (fcntl(self->_pfds[0], F_SETFL, flags) < 0) {
            printf("can't set pipe flags: %s\n", strerror(errno));
            return NULL;
        }

        flags = fcntl(self->_pfds[1], F_GETFL);
        if (flags < 0) {
            printf("can't get pipe flags: %s\n", strerror(errno));
            return NULL;
        }
        flags |= O_NONBLOCK;
        if (fcntl(self->_pfds[1], F_SETFL, flags) < 0) {
            printf("can't set pipe flags: %s\n", strerror(errno));
            return NULL;
        }

        bool work = true;

        while (work) {
			int nfds = 0;
			FD_ZERO(&read_fds);
			FD_ZERO(&write_fds);

			FD_SET(self->_pfds[0], &read_fds); // self-pipe trick
			nfds = std::max(nfds, self->_pfds[0]);

			FD_SET(sock, &read_fds);
			nfds = std::max(nfds, sock);

			for (size_t j = 0; j < connections.size(); ++j)
			{
				int fd = connections.at(j)._fd;
				FD_SET(fd, &read_fds);
				nfds = std::max(nfds, fd);
			}

            int selectResult = select(nfds + 1, &read_fds, NULL, NULL, NULL);

			if(selectResult <= 0)
				continue;

			for (int i = 0; i <= nfds; ++i) {
				if (FD_ISSET(i, &read_fds)) {
					if (i == self->_pfds[0]) {
						printf("quit\n");
						work = false;
						break;
					}

					if (i == sock) {
						printf("new connection\n");

						int fd = accept(sock, NULL, NULL);
						connections.push_back(Connection(fd));

						nfds = std::max(nfds, fd);

						FD_SET(fd, &read_fds);

						continue;
					}

					Connections::iterator it = std::find(connections.begin(), connections.end(), i);
					if (it != connections.end()) {
						size_t buffer_size = 4096;

						std::vector<char> buffer;
						buffer.resize(buffer_size);

						int connection = (*it)._fd;

						ssize_t bytesReceived = recv(connection, buffer.data(), buffer.size(), 0);

						if (bytesReceived == 0) {
							FD_CLR(it->_fd, &read_fds);
							::shutdown(it->_fd, SHUT_RDWR);
							close(it->_fd);
							connections.erase(it);

						} else if (bytesReceived < buffer_size) {
							bool handleResult = self->_handler->handle(buffer, static_cast<size_t>(bytesReceived),
																	   self, connection);
							if (!handleResult) {
								printf("warning: can't handle result\n");
							}
						} else if (bytesReceived == buffer_size) {
							printf("warning: receive buffer overflow\n");
						}
					}
				} else if (FD_ISSET(i, &write_fds)) {
					Connections::iterator it = std::find(connections.begin(), connections.end(), i);
					if (it != connections.end()) {
						printf("ready to write\n");
					}
				}
			}
		}

        for (size_t i = 0; i < connections.size(); ++i) {
            close(connections.at(i)._fd);
        }

        ::shutdown(sock, SHUT_RDWR);
        close(sock);

        close(self->_pfds[0]);
        close(self->_pfds[1]);

        printf("server socket thread end\n");
        return NULL;
    }

    bool sendData(const std::vector<char> &data, const Connection &conn) {
        return sendData(data.data(), data.size(), conn);
    }

    bool sendData(const std::string &data, const Connection &conn) {
        return sendData(data.data(), data.size(), conn);
    }

    bool sendData(const char *data, size_t size, const Connection &conn) {
        int summaryBytesSended = 0;
        do {
            char *ptr = const_cast<char *>(data) + summaryBytesSended;
            size_t balance = size - summaryBytesSended;

            ssize_t bytesSended = send(conn._fd, ptr, balance, MSG_NOSIGNAL);

//            printf("send %zi of %zi bytes to %d connection\n", size, bytesSended, conn._fd);
//            printf("data %s\n", data);

            summaryBytesSended += bytesSended;

        } while (summaryBytesSended < size);
        return true;
    }

    Handler *getHandler() {
        return _handler;
    }

    void setHandler(Handler *handler) {
        this->_handler = handler;
    }

    bool shutdown() {
        printf("shutdown\n");
        int savedErrno = errno;
        bool result = write(_pfds[1], "x", 1) < 0 && errno != EAGAIN;
        errno = savedErrno;
        return result;
    }

private:
    uint16_t _port;
    pthread_t _thread;

    Handler *_handler;
    int _pfds[2];
};

class WebServer : public ServerSocket::Handler {
public:
    typedef void (*request_handler_f)(const std::string &requestString, WebServer *);

    typedef void (WebServer::*request_handler_m)(const std::string &requestString);

	class Response{
	public:
		Response(const std::vector<char>& data = std::vector<char>(), bool valid = false) : data(data), valid(valid)
		{}

		std::vector<char> data;
		bool valid;
	};

    class RequestHandler {
    public:
        RequestHandler() :
                _webServer(NULL) {
        }

        virtual ~RequestHandler() {
        }

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

    typedef std::map<std::string, Ptr<RequestHandler> > RequestMap;

    class FileHandler : public RequestHandler {
        std::string _fileName;
    public:
        FileHandler(const std::string &fileName) :
                _fileName(fileName) {
        }

        virtual ~FileHandler() {
        }

        virtual Response getResponse() {
			const char *answer_template =
					"HTTP/1.1 200 OK\r\n"
					"Server: ShnaiderServer/2017-01-01\r\n"
					"Content-Type: %s\r\n"
					"Content-Length: %d\r\n"
					"Connection: keep-alive\r\n"
					"\r\n";

			std::vector<char> response;

			std::string filename = _webServer->getDirectory() + "/" + _fileName;

			struct stat path;
			stat(filename.c_str(), &path);
			if (!S_ISREG(path.st_mode)) {
				return Response();
			}

			FILE *file = fopen(filename.c_str(), "rb");

            if (file) {
				fseek(file, 0, SEEK_END);
				long size = ftell(file);
				rewind(file);

				std::string extension = _webServer->getExtension(_fileName);
				std::string mimeType = _webServer->getMimeTypeForExtension(extension);

				response.resize(strlen(answer_template) + size + 1024);
				snprintf(response.data(), response.size(), answer_template, mimeType.c_str(), size);

                char *ptr = response.data() + strlen(response.data());

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
    };

    class PageHandler : public RequestHandler {
        std::string _page;
    public:
        PageHandler(const std::string &page = 0) :
                _page(page) {
        }

        virtual ~PageHandler() {
        }

        virtual Response getResponse() {
            const char *answer_template = "HTTP/1.1 200 OK\r\n"
                    "Server: ShnaiderServer/2017-01-01\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: %d\r\n"
                    "Connection: keep-alive\r\n"
                    "\r\n"
                    "%s"
                    "\r\n"
            ;

            std::vector<char> answer_buffer;
            answer_buffer.resize(strlen(answer_template) + _page.size() + 1024);
            snprintf(answer_buffer.data(), answer_buffer.size(), answer_template, _page.size(), _page.c_str());
            return answer_buffer;
        }
    };

	class JsonHandler : public RequestHandler {
		std::string _page;
	public:
		JsonHandler(const std::string &page) :
				_page(page) {
		}

		virtual ~JsonHandler() {
		}

		virtual Response getResponse() {
			const char *answer_template = "HTTP/1.1 200 OK\r\n"
					"Server: ShnaiderServer/2017-01-01\r\n"
					"Content-Type: application/json\r\n"
					"Content-Length: %d\r\n"
					"Connection: keep-alive\r\n"
					"\r\n"
					"%s"
					"\r\n"
			;

			std::vector<char> answer_buffer;
			answer_buffer.resize(strlen(answer_template) + _page.size() + 1024);
			snprintf(answer_buffer.data(), answer_buffer.size(), answer_template, _page.size(), _page.c_str());
			return Response(answer_buffer, true);
		}
	};

	class FunctionHandler : public RequestHandler {
    public:
        typedef Response (*handler_t)();

        FunctionHandler(handler_t handler = 0) :
                _handler(handler) {
        }

        virtual ~FunctionHandler() {
        }

        virtual Response getResponse() {
            return _handler ? _handler() : Response();
        }

    private:
        handler_t _handler;
    };

    WebServer(uint16_t port = 8080) :
            _socket(new ServerSocket(port)) {
        _extToFileType.insert(std::make_pair("html", "text/html"));
        _extToFileType.insert(std::make_pair("js", "text/javascript"));
        _extToFileType.insert(std::make_pair("ico", "image/x-icon"));
        _extToFileType.insert(std::make_pair("png", "image/png"));
        _socket->setHandler(this);
    }

    ~WebServer() {
    }

    WebServer *setDirectory(const std::string &filesDirectory) {
        _filesDirectory = filesDirectory;
        return this;
    }

    const std::string &getDirectory() const {
        return _filesDirectory;
    }

    WebServer *addRequest(const std::string &requestString, RequestHandler *handler) {
        handler->setWebServer(this);
        _requestHandlers.insert(std::make_pair(requestString, handler));
        return this;
    }

    bool handle(const std::vector<char> &data, size_t bytesReceived, ServerSocket *socket,
                const ServerSocket::Connection &conn) {

        if (data.empty())
            return false;

        std::stringstream ss(data.data());

        std::string method;
        std::string request;

        ss >> method;
        ss >> request;

		printf("request: %s\n", request.c_str());

        if(checkAndResponseFile(request, socket, conn))
            return true;

        RequestMap::iterator it = _requestHandlers.find(request);
        if (it == _requestHandlers.end())
            return false;

        Response response = it->second->getResponse();

        return socket->sendData(response.data, conn);
    }

    bool checkAndResponseFile(const std::string &request, ServerSocket *socket,
                              const ServerSocket::Connection &conn) {
        if (getDirectory().empty())
            return false;
/*
        // "Content-Disposition: attachment; filename=%s\r\n"
        const char *answer_template =
            "HTTP/1.1 200 OK\r\n"
            "Server: ShnaiderServer/2017-01-01\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %d\r\n"
            "Connection: keep-alive\r\n"
            "\r\n";

        std::vector<char> response;

        std::string filename = getDirectory() + request;

        struct stat path;
        stat(filename.c_str(), &path);
        if (!S_ISREG(path.st_mode)) {
            return false;
        }

        FILE *file = fopen(filename.c_str(), "rb");

        if (file) {
            fseek(file, 0, SEEK_END);
            long size = ftell(file);
            rewind(file);

            std::string extension = getExtension(request);
            std::string mimeType = getMimeTypeForExtension(extension);

            response.resize(strlen(answer_template) + size + 1024);
            snprintf(response.data(), response.size(), answer_template, mimeType.c_str(), size);

            char *ptr = response.data() + strlen(response.data());

            size_t bytesRead = fread(ptr, 1, static_cast<size_t>(size), file);

            ptr += bytesRead;

            memcpy(ptr, "\r\n", 2);

            if (bytesRead != size) {
                printf("warning: read size not match\n");
            }

            fclose(file);

            return socket->sendData(response, conn);

        } else {
			return false;
        }
*/

		FileHandler fileHandler(request);
		fileHandler.setWebServer(this);
		Response response = fileHandler.getResponse();
		if (response.valid){
			socket->sendData(response.data, conn);
		}
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
    std::map<std::string, Ptr<RequestHandler> > _requestHandlers;
    std::string _filesDirectory;
    std::map<std::string, std::string> _extToFileType;
};

pthread_mutex_t mutex;
pthread_cond_t cond;

bool programWork = true;

void signal_handler(int) {
    pthread_mutex_lock(&mutex);
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);
}

WebServer::Response stopProgramRequest() {
    programWork = false;
    signal_handler(0);
    return WebServer::Response();
}

int main() {
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&cond, NULL);

    while (programWork) {
        signal(SIGINT, signal_handler);

        Ptr<WebServer> ws((new WebServer(9001))
            ->setDirectory("static")
            ->addRequest("/", new WebServer::FileHandler("index.html"))
			->addRequest("/test_json", new WebServer::JsonHandler("{\"test\": 42}"))
            ->addRequest("/quit", new WebServer::FunctionHandler(stopProgramRequest))
        );

        pthread_mutex_lock(&mutex);
        pthread_cond_wait(&cond, &mutex);
        pthread_mutex_unlock(&mutex);

        printf("exit\n");
    }
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);
    return 0;
}


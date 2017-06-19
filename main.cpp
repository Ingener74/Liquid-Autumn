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
#include <algorithm>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <limits>

// json: https://github.com/zserge/jsmn

#define dws_assert(cond, message) if(!(cond)) throw std::runtime_error(message);
#define dws_assertx(cond, format, ...) if(!(cond)) throw std::runtime_error(xsnprintf(128, format, __VA_ARGS__));

namespace dws {

template<typename T>
class clean_allocator {
public :
	typedef T value_type;
	typedef value_type* pointer;
	typedef const value_type* const_pointer;
	typedef value_type& reference;
	typedef const value_type& const_reference;
	typedef std::size_t size_type;
	typedef std::ptrdiff_t difference_type;
public :

	template<typename U>
	struct rebind {
		typedef clean_allocator<U> other;
	};

public :
	clean_allocator() {}
	inline ~clean_allocator() {}
	clean_allocator(clean_allocator const&) {}
	template<typename U>
	clean_allocator(clean_allocator<U> const&) {}

	inline pointer address(reference r) { return &r; }
	inline const_pointer address(const_reference r) { return &r; }

	inline pointer allocate(size_type cnt, typename std::allocator<void>::const_pointer = 0) {
		pointer new_memory = reinterpret_cast<pointer>(::operator new(cnt * sizeof (T)));
		memset(new_memory, 0, cnt * sizeof(T));
		return new_memory;
	}
	inline void deallocate(pointer p, size_type n) {
		::operator delete(p);
	}
	//    size
	inline size_type max_size() const {
		return std::numeric_limits<size_type>::max() / sizeof(T);
	}

	inline void construct(pointer p, const T& t) {
		new(p) T(t);
	}
	inline void destroy(pointer p) {
		p->~T();
	}

	inline bool operator==(clean_allocator const&) { return true; }
	inline bool operator!=(clean_allocator const& a) { return !operator==(a); }
};

}

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
    Ptr(T* t = NULL) : t(t) {}
    ~Ptr() { if (t) delete t; }
	T* operator->() { return t ? t : throw std::runtime_error("pointer is null"); }
private:
	T* t;
};

template<typename T>
class XPtr {
public:
    XPtr(T* t = NULL) : t(t) {}
    ~XPtr() { if (t) delete t; t = NULL; }
	T* operator->() { return t ? t : throw std::runtime_error("pointer is null"); }
	const T* operator->() const { return t ? t : throw std::runtime_error("pointer is null"); }
	XPtr(const XPtr& rhs) { *this = rhs; }
	XPtr& operator=(const XPtr& rhs) {
		if (this != &rhs) {
			if (t) {
				delete t;
				t = NULL;
			}
			t = rhs.t->clone();
		}
		return *this;
	}
private:
	T* t;
};

namespace json {

#define json_assert(cond, message) if(!(cond)) throw std::runtime_error(message);
#define json_assertx(cond, format, ...) if(!(cond)) throw std::runtime_error(xsnprintf(128, format, __VA_ARGS__));


template<typename T>
class CreateVector {
public:
	CreateVector(const T& t) {
		v.push_back(t);
	}

	CreateVector& operator()(const T& t) {
		v.push_back(t);
		return *this;
	}

	operator std::vector<T>() const {
		return v;
	}

	std::vector<T> v;
};

bool any_of(const std::vector<char>& symbols, char sym) {
	std::vector<char>::const_iterator it = std::find(symbols.begin(), symbols.end(), sym);
	return it != symbols.end();
}

bool all_of(const std::vector<char>& symbols, const std::string& string) {
	bool result = !string.empty();
	for (std::string::const_iterator ch = string.begin(); ch != string.end(); ++ch) {
		result &= any_of(symbols, *ch);
	}
	return result;
}

bool isTrue(const std::string& string) {
	if (string.empty() || string.size() != 4)
		return false;
	return
		(string.at(0) == 'T' || string.at(0) == 't') &&
		(string.at(1) == 'R' || string.at(1) == 'r') &&
		(string.at(2) == 'U' || string.at(2) == 'u') &&
		(string.at(3) == 'E' || string.at(3) == 'e');
}
bool isFalse(const std::string& string) {
	if (string.empty() || string.size() != 5)
		return false;
	return
		(string.at(0) == 'F' || string.at(0) == 'f') &&
		(string.at(1) == 'A' || string.at(1) == 'a') &&
		(string.at(2) == 'L' || string.at(2) == 'l') &&
		(string.at(3) == 'S' || string.at(3) == 's') &&
		(string.at(4) == 'E' || string.at(4) == 'e');
}

static std::vector<char> integer_ = CreateVector<char>('0')('1')('2')('3')('4')('5')('6')('7')('8')('9')('-');
static std::vector<char> float_ = CreateVector<char>('0')('1')('2')('3')('4')('5')('6')('7')('8')('9')('.')('e')('E')('+')('-');
static std::vector<char> true_ = CreateVector<char>('t')('T')('r')('R')('u')('U')('e')('E');
static std::vector<char> false_ = CreateVector<char>('f')('F')('a')('A')('l')('L')('s')('S')('e')('E');

struct Token {
	enum Type {
		ObjectStart,
		ObjectEnd,
		ArrayStart,
		ArrayEnd,
		Semicolon,
		Comma,
		Integer,
		Float,
		String,
		Bool,
	};

	Token(Type type, const std::string& value = std::string()) : type(type), value(value)
	{}

	friend std::ostream& operator<<(std::ostream& os, const Token& token)
	{
		static std::map<Type, std::string> tokenTypes =
				CreateMap<Type, std::string>
						(ObjectStart, "{")
						(ObjectEnd, "}")
						(ArrayStart, "[")
						(ArrayEnd, "]")
						(Semicolon, ":")
						(Comma, ",")
						(Integer, "Integer")
						(Float, "Float")
						(String, "String")
						(Bool, "Bool");
		;
		os << "type: " << tokenTypes.at(token.type) << (token.value.empty() ? "" : " value: " + token.value);
		return os;
	}

	Type type;
	std::string value;
};

typedef std::vector<Token> Tokens;

Tokens tokenize(const std::string& string) {
	Tokens tokens;
	for (std::string::const_iterator ch = string.begin(); ch != string.end(); ++ch) {
		if (*ch == '{') {
			tokens.push_back(Token(Token::ObjectStart));
		} else if (*ch == '}') {
			tokens.push_back(Token(Token::ObjectEnd));
		} else if (*ch == '[') {
			tokens.push_back(Token(Token::ArrayStart));
		} else if (*ch == ']') {
			tokens.push_back(Token(Token::ObjectEnd));
		} else if (*ch == ':') {
			tokens.push_back(Token(Token::Semicolon));
		} else if (*ch == ',') {
			tokens.push_back(Token(Token::Comma));
		} else if (*ch == '\"') {
			std::string token;
			while (*++ch != '\"')
				token.push_back(*ch);
			tokens.push_back(Token(Token::String, token));
		} else if (any_of(integer_, *ch) || any_of(float_, *ch)) {
			std::string token;
			Token::Type type = Token::Integer;
			bool isInteger;
			bool isFloat;
			do {
				isInteger = any_of(integer_, *ch);
				isFloat = any_of(float_, *ch);
				if (isFloat)
					type = Token::Float;
				if (isInteger || isFloat)
					token.push_back(*ch++);
			} while (isInteger || isFloat);
			tokens.push_back(Token(type, token));
			ch--;
		} else if (any_of(true_, *ch) || any_of(false_, *ch)) {
			std::string token;
			token.push_back(*ch++);
			while(any_of(true_, *ch) || any_of(false_, *ch))
				token.push_back(*ch++);
			tokens.push_back(Token(Token::Bool, isTrue(token) ? "true" : isFalse(token) ? "false" : throw std::runtime_error("something wrong, not true and not false")));
			ch--;
		} else if(*ch == ' ' || *ch == '\n' || *ch == '\t') {
		} else throw std::runtime_error(xsnprintf(64, "invalid symbol %d", static_cast<int>(*ch)));
	}
	return tokens;
}

/**
 * Json grammar rules description
 *
 * Json    ::= Object | Array
 * Object  ::= ObjectStart, Records, ObjectEnd | ObjectStart, ObjectEnd
 * Array   ::= ArrayStart, Values, ArrayEnd | ArrayStart, ArrayEnd
 * Values  ::= Value, Comma, Values | Value
 * Value   ::= Integer | String | FLoat | Bool | Array | Object
 * Records ::= Record, Comma, Records | Record
 * Record  ::= String, Semicolon, Value
 */

enum NonTerminals {
	Json = 100,
	Empty,
	Obj,
	Arr,
	Records,
	Record,
	Values,
	Value,

	NonTerminalsCount,
};

typedef std::vector<int> Items;
typedef std::vector<Items> Variants;
typedef std::map<NonTerminals, Variants> Rules;

typedef CreateMap<NonTerminals, Variants> CreateRules;
typedef CreateVector<Items> CreateItems;
typedef CreateVector<int> CreateVariant;

static Rules jsonGrammarRules = CreateRules
		(Json, CreateItems
				(CreateVariant(Obj))
				(CreateVariant(Arr))
		)
		(Obj, CreateItems
				(CreateVariant(Token::ObjectStart)(Records)(Token::ObjectEnd))
				(CreateVariant(Token::ObjectStart)(Token::ObjectEnd))
		)
		(Arr, CreateItems
				(CreateVariant(Token::ArrayStart)(Values)(Token::ArrayEnd))
				(CreateVariant(Token::ArrayStart)(Token::ArrayEnd))
		)
		(Records, CreateItems
				(CreateVariant(Record)(Token::Comma)(Records))
				(CreateVariant(Record))
		)
		(Record, CreateItems
				(CreateVariant(Token::String)(Token::Semicolon)(Value))
		)
		(Values, CreateItems
				(CreateVariant(Value)(Token::Comma)(Values))
				(CreateVariant(Value))
		)
		(Value, CreateItems
				(CreateVariant(Obj))
				(CreateVariant(Arr))
				(CreateVariant(Token::String))
				(CreateVariant(Token::Float))
				(CreateVariant(Token::Integer))
				(CreateVariant(Token::Bool))
		)
;

void parse(const Tokens& tokens) {
}

class Type {
public:
	Type()
	{}

	virtual Type* clone() const = 0;

	virtual std::string stringify() const = 0;
};

#define JSON_TYPE(Primary, secondary)           \
class Primary : public Type {                   \
public:                                         \
    Primary(secondary value) : value(value){}   \
    virtual Type* clone() const                 \
    {                                           \
        return new Primary(*this);              \
    }                                           \
    virtual std::string stringify() const {     \
        std::stringstream stream;               \
        stream << value;                        \
        return stream.str();                    \
    }                                           \
    secondary value;                            \
};

JSON_TYPE(Integer, int64_t)
//JSON_TYPE(String, std::string)
JSON_TYPE(Float, double)
//JSON_TYPE(Bool, bool)

class String : public Type {
public:
    String(std::string const& value) : value(value){}
    virtual Type* clone() const
    {
        return new String(*this);
    }
    virtual std::string stringify() const {
        std::stringstream stream;
        stream << "\"" << value << "\"";
        return stream.str();
    }
    std::string value;
};

class Bool : public Type {
public:
    Bool(bool value) : value(value){}
    virtual Type* clone() const {
        return new Bool(*this);
    }
    virtual std::string stringify() const {
        std::stringstream stream;
        stream << (value ? "true" : "false");
        return stream.str();
    }
    bool value;
};

class Array;

class Object : public Type {
public:
	typedef std::map<std::string, XPtr<Type> > Fields;
	Object() {}

	virtual Type* clone() const {
		return new Object(*this);
	}

	virtual std::string stringify() const
	{
		std::stringstream stream;
		stream << "{";
		for (Fields::const_iterator it = fields.begin(); it != fields.end(); ++it) {
			if (it != fields.begin()) {
				stream << ", ";
			}
			stream << "\"" << it->first << "\"" << ": " << it->second->stringify();
		}
		stream << "}";
		return stream.str();
	}

	Object& operator()(const std::string& key, const std::string& v) { return add<String>(key, v); }
	Object& operator()(const std::string& key, const char* v) { return add<String>(key, v); }
	Object& operator()(const std::string& key, int64_t v) { return add<Integer>(key, v); }
	Object& operator()(const std::string& key, int v) { return add<Integer>(key, static_cast<int64_t>(v)); }
	Object& operator()(const std::string& key, bool v) { return add<Bool>(key, v); }
	Object& operator()(const std::string& key, double v) { return add<Float>(key, v); }
	Object& operator()(const std::string& key, const Object& v) { return add<Object>(key, v); }
	Object& operator()(const std::string& key, const Array& v);

	template<typename T, typename V>
	Object& add(const std::string& key, const V& v) {
		json_assert(fields.insert(std::make_pair(key, new T(v))).second, "can't insert field");
		return *this;
	};

	friend std::ostream& operator<<(std::ostream& os, const Object& object)
	{
		return os << object.stringify();
	}

	std::map<std::string, XPtr<Type>,
			std::less<std::string>,
			dws::clean_allocator<std::pair<const std::string, XPtr<Type> > > > fields;
};

class Array : public Type {
public:
	typedef std::vector<XPtr<Type>, dws::clean_allocator<XPtr<Type> > > Fields;
	Array() {}

	virtual Array* clone() const {
		return new Array(*this);
	}

	Array& operator()(const std::string& v) { return add<String>(v); }
	Array& operator()(const char* v) { return add<String>(v); }
	Array& operator()(int64_t v) { return add<Integer>(v); }
	Array& operator()(int v) { return add<Integer>(static_cast<int64_t>(v)); }
	Array& operator()(bool v) { return add<Bool>(v); }
	Array& operator()(double v) { return add<Float>(v); }
	Array& operator()(const Object& v) { return add<Object>(v); }
	Array& operator()(const Array& v) { return add<Array>(v); }

	template<typename T, typename V>
	Array& add(const V& v) {
		fields.push_back(new T(v));
		return *this;
	};

	virtual std::string stringify() const {
		std::stringstream stream;
		stream << "[";
		for (Fields::const_iterator it = fields.begin(); it != fields.end(); ++it) {
			if (it != fields.begin())
				stream << ", ";
			stream << (*it)->stringify();
		}
		stream << "]";
		std::string string = stream.str();
		return string;
	}

	friend std::ostream& operator<<(std::ostream& os, const Array& array)
	{
		return os << array.stringify();
	}

	Fields fields;
};

Object& Object::operator()(const std::string& key, const Array& v)
{
	return add<Array>(key, v);
}

void jsonParse(const char* json) {
}

}

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

    virtual void handleRead(const std::vector<char>& data, Connection* connection) = 0;
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
    ConnectionListener(uint16_t port, ConnectionHandler* connectionHandler, Io* io)
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
		connectionHandler->handleRead(buffer, this);
    } else if (bytesReceived == buffer_size) {
        dws_assert(false, "not implemented");
    } else if (bytesReceived < 0) {
        throw std::runtime_error(xsnprintf(128, "recv error: %s", strerror(errno)));
    }
}

class Pipes : public IoHandler {
public:
    Pipes(bool* work, Io* io) : work(work) {
        dws_assertx(pipe(pfds) >= 0, "can't create pipes: %s\n", strerror(errno));

        int flags = 0;

        flags = fcntl(pfds[0], F_GETFL);
        dws_assertx(flags >= 0, "can't get pipe flags: %s\n", strerror(errno));

        flags |= O_NONBLOCK;
        dws_assertx(fcntl(pfds[0], F_SETFL, flags) >= 0, "can't set pipe flags: %s\n", strerror(errno));

        flags = fcntl(pfds[1], F_GETFL);
        dws_assertx(flags >= 0, "can't get pipe flags: %s\n", strerror(errno));

        flags |= O_NONBLOCK;
        dws_assertx(fcntl(pfds[1], F_SETFL, flags) >= 0, "can't set pipe flags: %s\n", strerror(errno));

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
            bool work = true;

            Io io;
            ConnectionListener connectionListener(self->port, self->connectionHandler, &io);
            Pipes pipes(&work, &io);

            self->pipes = &pipes;

            while (work)
                try {
                    io.wait();
                } catch (std::runtime_error const& e) {
                    printf("io error: %s\n", e.what());
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

class ResponseBuilder {
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

	ResponseBuilder()
			: protocol(Http)
			, protocolVersionMajor(1)
			, protocolVersionMinor(1)
			, errorCode(OK_200)
			, serverName("ShnaiderServer/2017-01-01")
			, contentType("text/html")
			, connectionType(KeepAlive)
			, stream(&buffer)
	{}

	ResponseBuilder& setProtocol(Protocol protocol) {
		this->protocol = protocol;
		return *this;
	}

	ResponseBuilder& setProtocolVersion(int major, int minor) {
		this->protocolVersionMajor = major;
		this->protocolVersionMinor = minor;
		return *this;
	}

	ResponseBuilder& setErrorCode(ErrorCode errorCode) {
		this->errorCode = errorCode;
		return *this;
	}

	ResponseBuilder& setServerName(const std::string& serverName) {
		this->serverName = serverName;
		return *this;
	}

	ResponseBuilder& setContentType(const std::string& contentType) {
		this->contentType = contentType;
		return *this;
	}

	ResponseBuilder& setContentTypeByFileName(const std::string& fileName) {
		contentType = getContentTypeForExtension(getExtension(fileName));
		return *this;
	}

	ResponseBuilder& setConnection(ConnectionType connectionType) {
		this->connectionType = connectionType;
		return *this;
	}

	ResponseBuilder& build(const ByteBuffer& content = ByteBuffer()) {
		stream << (protocol == Http ? "HTTP" : "") << "/" << protocolVersionMajor << "." << protocolVersionMinor << " "
			   << errorCode << " " << errorCodeCommentMap[errorCode] << "\r\n";

		stream << "Server: " << serverName << "\r\n";
		stream << "Content-Type: " << contentType << "\r\n";
		stream << "Content-Length: " << content.size() << "\r\n";
		stream << "Connection: " << (connectionType == KeepAlive ? "keep-alive" : "close") << "\r\n";

		stream << "\r\n";
		stream.write(content.data(), content.size());
		stream << "\r\n";

		return *this;
	}

	ResponseBuilder& build(const std::string& content) {
		return build(std::vector<char>(content.begin(), content.end()));
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

ResponseBuilder::ErrorCodeCommentMap ResponseBuilder::errorCodeCommentMap =
		CreateMap<ResponseBuilder::ErrorCode, const char*>
				(ResponseBuilder::OK_200                    , "Ok"                              )
				(ResponseBuilder::NotFound_404              , "Not Found"                       )
				(ResponseBuilder::NotImplemented_501        , "Not Implemented"                 )
;

ResponseBuilder::ExtensionToContentType ResponseBuilder::extensionToContentType =
		CreateMap<std::string, std::string>
				("html"    , "text/html"          )
				("js"      , "text/javascript"    )
				("css"     , "text/css"           )
				("ico"     , "image/x-icon"       )
				("png"     , "image/png"          )
;

class RequestHandler {
public:
    RequestHandler() : _webServer(NULL) {}

    virtual ~RequestHandler() {}

    virtual void getResponse(const Request& request, Connection* connection) = 0;

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
    FileHandler(const std::string& fileName, bool skipIfNotExist = false) :
            _fileName(fileName), fileSendedSuccessfuly(false), skipIfNotExist(skipIfNotExist), fileNotExist(false) {
    }

    virtual ~FileHandler() {
    }

    virtual void getResponse(const Request& request, Connection* connection);

	bool fileSendedSuccessfuly;
	bool skipIfNotExist;
	bool fileNotExist;
};

class PageHandler : public RequestHandler {
    std::string _page;
public:
    PageHandler(const std::string& page = 0) : _page(page) {}

    virtual ~PageHandler() {}

    virtual void getResponse(const Request& request, Connection* connection) {
		ResponseBuilder().
				setErrorCode(ResponseBuilder::OK_200).
				setContentType("text/html").
				setConnection(ResponseBuilder::KeepAlive).
				build(_page).
				send(connection);
    }
};

class JsonHandler : public RequestHandler {
    std::string _page;
public:
    JsonHandler(const std::string& page) : _page(page) {}

    virtual ~JsonHandler() {}

    virtual void getResponse(const Request& request, Connection* connection) {
		ResponseBuilder().
				setErrorCode(ResponseBuilder::OK_200).
				setContentType("application/json").
				setConnection(ResponseBuilder::KeepAlive).
				build(_page).
				send(connection);
    }
};

class FunctionHandler : public RequestHandler {
public:
    typedef void (* handler_t)(const Params&);

    FunctionHandler(handler_t handler = 0) : handler(handler) {}

    virtual void getResponse(const Request& request, Connection* connection) {
        if (handler)
			handler(request.params);
    }

private:
    handler_t handler;
};

class WebServer : public ConnectionHandler {
public:
    typedef std::map<Request, RequestHandler*> RequestMap;

    WebServer(uint16_t port = 8080) :
            _socket(new ServerSocket(port, this)) {
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

    void handleRead(const std::vector<char>& data, Connection* connection) {
        dws_assert(!data.empty(), "data is empty")

        std::stringstream ss(data.data());

        std::string methodStr;
        std::string requestStr;

        ss >> methodStr;
        ss >> requestStr;

        printf("%s: %s\n", methodStr.c_str(), requestStr.c_str());
        const Request& request = Request(methodStr, requestStr);

        if (checkAndResponseWithFile(request, connection))
            return;

        std::cout << request << std::endl;

        RequestMap::iterator it = _requestHandlers.find(request);
        if (it == _requestHandlers.end()/* && (request.method & it->first.method)*/) {
            ResponseBuilder().
                    setErrorCode(ResponseBuilder::NotImplemented_501).
                    build().
                    send(connection);
            return;
        }

        it->second->getResponse(request, connection);
        return;
    }

    bool checkAndResponseWithFile(const Request& request, Connection* connection) {
        if (getDirectory().empty())
            return false;

        FileHandler fileHandler(request.request, true);
        fileHandler.setWebServer(this);
        fileHandler.getResponse(request, connection);

        return fileHandler.fileSendedSuccessfuly;
    }

    bool shutdown() {
        return _socket->shutdown();
    }

private:
    Ptr<ServerSocket> _socket;
    RequestMap _requestHandlers;
    std::string _filesDirectory;
};

void FileHandler::getResponse(const Request& request, Connection* connection)
{
	if (_fileName.empty()) {
		if (skipIfNotExist){
			fileNotExist = true;
		} else {
			ResponseBuilder().
					setErrorCode(ResponseBuilder::NotFound_404).
					build().
					send(connection);
		}
		return;
	}
    std::string sep;
    if (_fileName.at(0) != '/')
        sep = "/";

    std::string filename = _webServer->getDirectory() + sep + _fileName;

    struct stat path;
    stat(filename.c_str(), &path);
    if (!S_ISREG(path.st_mode)) {
		if (skipIfNotExist){
			fileNotExist = true;
		} else {
			ResponseBuilder().
					setErrorCode(ResponseBuilder::NotFound_404).
					build().
					send(connection);
		}
        return;
    }

    FILE* file = fopen(filename.c_str(), "rb");

    if (file) {
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        rewind(file);

		ByteBuffer buffer(size);
        size_t bytesRead = fread(buffer.data(), 1, static_cast<size_t>(size), file);
		dws_assertx(bytesRead == size, "fail read file %s", _fileName.c_str());

        fclose(file);

		ResponseBuilder().
				setErrorCode(ResponseBuilder::OK_200).
				setContentTypeByFileName(_fileName).
				build(buffer).
				send(connection);

		fileSendedSuccessfuly = true;
    } else {
		if (skipIfNotExist) {
			fileNotExist = true;
		} else {
			ResponseBuilder().
					setErrorCode(ResponseBuilder::NotFound_404).
					build().
					send(connection);
		}
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

void stopProgramRequest(const Params&) {
    programWork = false;
    signal_handler(0);
}

int main() {
	try  {
		typedef std::vector<json::Token> Tokens;

		const char* test_json =
				"{"
						"\"Pasha\": \"Xyu\", \n"
						"\"Pi\": 3.1415, \n"
						"\"meaningOfLife\": 42, \n"
						"\"FuckingString\": \"Tra ta ta\", \n"
						"\"MyHeartIsBroken\": True, \n"
						"\t\"AllBad\": False\n"
				"}";

		Tokens tokens = json::tokenize(test_json);

		for (Tokens::iterator it = tokens.begin(); it != tokens.end(); ++it) {
			std::cout << *it << std::endl;
		}

		std::cout << json::Object()
				("Test String", "string")
				("Test object",
					json::Object()
							("Foo", 32)
							("Bar", json::Array()
									(564)
									("Test")
							)
							("Quuz", json::Array()
									(42)
									(false)
							)
					)
				("Test Integer", 42)
				("Test Float", 3.1415)
				("Test Bool", false) << std::endl;

	} catch (std::exception const& e) {
		std::cerr << e.what() << std::endl;
	}

    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&cond, NULL);

    while (programWork) {
        signal(SIGINT, signal_handler);

        Ptr<WebServer> ws((new WebServer(9001))
            ->setDirectory("static")
            ->addRequest(Request(Request::ALL, "/"            ), new FileHandler("index.html"))
            ->addRequest(Request(Request::ALL, "/test_json"   ), new JsonHandler("{\"test\": 123}"))
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


#ifndef __pingWrapper__
#define __pingWrapper__

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <thread>
#include <vector>
#include <map>
#include <string>
#include <functional>

class pingWrapper
{
public:
	pingWrapper();
	~pingWrapper();

	static pingWrapper* getInstance();
	void checkNetSpeed(const std::vector<std::string>& vec);
	//----
	int  getCurProcessId();
	int  getTime();
protected:
	void init();
	void pingAll(const std::vector<std::string>& vec);
	void ping(const char* ip);

	bool isTimeOut();
	bool isReachGoalIp();
private:
	std::map<std::string, int> m_pingTimeMap;
};

#endif // __pingWrapper_SCENE_H__
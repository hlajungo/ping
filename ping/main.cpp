#include "pingWrapper.h"
#include <vector>
#include <string>
int main()
{
	std::vector<std::string> ipsVec = { "www.baidu.com", "www.taobao.com", "www.qq.com" };
	pingWrapper::getInstance()->checkNetSpeed(ipsVec);

	getchar();
	return 0;
}
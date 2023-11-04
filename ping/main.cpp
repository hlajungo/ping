#include "pingWrapper.h"
#include <vector>
#include <string>
int main()
{
	std::vector<std::string> ipsVec = { "music.youtube.com", "moodle.ncnu.edu.tw", "openai.com","openai.com","openai.com" };
	pingWrapper::getInstance()->checkNetSpeed(ipsVec);
	
		
	getchar();
	return 0;

}
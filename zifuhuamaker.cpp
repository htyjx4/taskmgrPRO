#include<bits/stdc++.h>
#include"lib_paste.cpp"
using namespace std;
int main(){
    cout<<"¸´ÖÆ×Ö·û»­,½áÊøÎª'STOP'ÐÐ\n";
	vector<string>v;
	while(1){
		string s;
		getline(cin,s);
		if(s=="STOP") break;
		v.push_back(s);
	}
	int l = v.size();
	string name;
	cout<<"input ×Ö·û»­Ãû(english)\n";cin>>name;
	stringstream ss;
	cout<<"make code\n";
	ss<<"#include<bits/stdc++.h>\n"<<"using namespace std;\n"
	<<"//by zifuhua maker\n"<<"int zfh_"<<name<<"(){\n";
	for(string s : v){
		ss<<"    cout<<\"";
		for(char c : s){
			if(c=='"') ss<<"\\\"";
			else if(c=='\'') ss<<"\\'";
			else if(c=='\\') ss<<"\\\\";
			else if(c=='\n') ss<<"\\n";
			else ss<<c;
		}
		ss<<"\\n\";\n";
	}
	ss<<"return 0;\n}\n";
	cout<<"¸´ÖÆµ½¼ôÇÐ°å\n";
	str2paste(ss.str());
	return 0;
}


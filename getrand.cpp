#include<bits/stdc++.h>
#include<iostream>
#include<cstdio>
#include<cmath>
#include<queue>
using namespace std;
int size,seed,mod;
int main(){
	cout<<"input size,seed,mod\n";
	cin>>size>>seed>>mod;
	cout<<"int randn["<<size+1<<"] = {";
	srand(seed);
	for(int i = 0;i<size;i++){
		cout<<rand()%mod<<",";
	}
	cout<<"0};";
	return 0;
}


//
//  ViewController.m
//  LocalAuthDemo
//
//  Created by apple on 2017/11/1.
//  Copyright © 2017年 CNFIDO. All rights reserved.
//

#import "ViewController.h"
#import "SVProgressHUD/SVProgressHUD.h"
#import <LocalAuthentication/LocalAuthentication.h>
#import <sys/utsname.h>
#include <dlfcn.h>
#import <sys/stat.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
	[super viewDidLoad];
	//判断当前设备是否越狱
	if([self isJailbroken]){
		NSLog(@"该设备已越狱");
	}
	
	//判断当前手机型号，方便进行UI提示语的修改
	struct utsname systemInfo;
	uname(&systemInfo);
	NSString*platform = [NSString stringWithCString: systemInfo.machine encoding:NSASCIIStringEncoding];
	//编号与型号对照表 https://www.theiphonewiki.com/wiki/Models
	NSLog(@"当前设备编号：%@",platform);
	
	//判断当前设备指纹\面容是否可用
	[self touchIDIsEnrolled];
}
-(BOOL)touchIDIsEnrolled{
	//指纹||faceID
	LAContext * context =  [[LAContext alloc]init];
	NSError * error = nil;
	if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]){
		NSLog(@"Touch ID 可用");
		return YES;
	}else{
		if(error.code == LAErrorTouchIDNotEnrolled){
			NSLog(@"Touch ID 没有可用的指纹");
		}else if (error.code == LAErrorPasscodeNotSet){
			NSLog(@"没有设置开机密码");
		}else if (error.code == LAErrorTouchIDNotAvailable){
			NSLog(@"Touch ID 在当前设备不可用");
		}
		return NO;
	}
}
- (IBAction)btnAction:(id)sender {
	
	LAContext * context =  [[LAContext alloc]init];
	if (@available(iOS 11.0, *)) {
		context.localizedReason = @"dadas";
	} else {
		// Fallback on earlier versions
	}
	context.localizedFallbackTitle = @"密码";
	NSError * error = nil;
	if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
		NSData * LocalAuthprintData = [context evaluatedPolicyDomainState];
		NSLog(@"PolicyDomainState>>>>%@",LocalAuthprintData);
		NSString *reasonStr = @"";
		if (@available(iOS 11.0, *)){
			if (context.biometryType==LABiometryTypeFaceID) {
				reasonStr = @"通过前置摄像头验证已有FaceID";
			}else if (context.biometryType==LABiometryTypeTouchID){
				reasonStr = @"通过手机指纹键验证已有手机指纹";
			}
		}
		
		[context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:reasonStr reply:^(BOOL success, NSError * _Nullable error) {
			
			if (success) {
				//指纹验证成功
				[SVProgressHUD showSuccessWithStatus:@"验证成功"];
			}
			NSLog(@"code== %ld,localizedFailureReason==%@",error.code,error.localizedDescription);
			//指纹验证错误
			if (error.code == LAErrorAuthenticationFailed) {// -1: 连续三次指纹识别错误
				[SVProgressHUD showErrorWithStatus:@"连续三次识别错误"];
			}else if (error.code == LAErrorUserCancel){// -2: 在TouchID对话框中点击了取消按钮
				[SVProgressHUD showErrorWithStatus:@"点击了取消按钮"];
			}else if (error.code == LAErrorUserFallback){// -3: TouchID对话框被用户回退（点击了副选框）
				[SVProgressHUD showErrorWithStatus:@"被用户回退"];
			}else if (error.code == LAErrorSystemCancel){// -4: TouchID对话框被系统取消，例如按下Home或者电源键
				[SVProgressHUD showErrorWithStatus:@"被系统取消"];
			}else if (error.code == LAErrorTouchIDLockout){ // -8: 连续五次指纹识别错误，TouchID功能被锁定，下一次需要输入系统密码
				if ([error.localizedDescription containsString:@"disabled for unlock"]) {
					[SVProgressHUD showErrorWithStatus:@"未开启iPhone解锁"];
				}else{
					[SVProgressHUD showErrorWithStatus:@"连续五次识别错误"];
				}
			} else {
				
			}
			
		}];
		
	}else {
		//不支持指纹认证设备
		NSLog(@"error==%@",error);
	}
	
}

- (void)didReceiveMemoryWarning {
	[super didReceiveMemoryWarning];
	// Dispose of any resources that can be recreated.
}
- (BOOL)isJailbroken
{
	//以下检测的过程是越往下，越狱越高级
	
	//    /Applications/Cydia.app, /privte/var/stash
	BOOL jailbroken = NO;
	NSString *cydiaPath = @"/Applications/Cydia.app";
	NSString *aptPath = @"/private/var/lib/apt/";
	if ([[NSFileManager defaultManager] fileExistsAtPath:cydiaPath]) {
		jailbroken = YES;
	}
	if ([[NSFileManager defaultManager] fileExistsAtPath:aptPath]) {
		jailbroken = YES;
	}
	
	//可能存在hook了NSFileManager方法，此处用底层C stat去检测
	struct stat stat_info;
	if (0 == stat("/Library/MobileSubstrate/MobileSubstrate.dylib", &stat_info)) {
		jailbroken = YES;
	}
	if (0 == stat("/Applications/Cydia.app", &stat_info)) {
		jailbroken = YES;
	}
	if (0 == stat("/var/lib/cydia/", &stat_info)) {
		jailbroken = YES;
	}
	if (0 == stat("/var/cache/apt", &stat_info)) {
		jailbroken = YES;
	}
	//    /Library/MobileSubstrate/MobileSubstrate.dylib 最重要的越狱文件，几乎所有的越狱机都会安装MobileSubstrate
	//    /Applications/Cydia.app/ /var/lib/cydia/绝大多数越狱机都会安装
	//    /var/cache/apt /var/lib/apt /etc/apt
	//    /bin/bash /bin/sh
	//    /usr/sbin/sshd /usr/libexec/ssh-keysign /etc/ssh/sshd_config
	
	//可能存在stat也被hook了，可以看stat是不是出自系统库，有没有被攻击者换掉
	//这种情况出现的可能性很小
	int ret;
	Dl_info dylib_info;
	int (*func_stat)(const char *,struct stat *) = stat;
	if ((ret = dladdr(func_stat, &dylib_info))) {
		if (strcmp(dylib_info.dli_fname, "/usr/lib/system/libsystem_kernel.dylib")) {   //不相等，肯定被攻击了，相等为0
			jailbroken = YES;
		}
	}
	
	//还可以检测链接动态库，看下是否被链接了异常动态库，但是此方法存在appStore审核不通过的情况，这里不作罗列
	//通常，越狱机的输出结果会包含字符串： Library/MobileSubstrate/MobileSubstrate.dylib——之所以用检测链接动态库的方法，是可能存在前面的方法被hook的情况。这个字符串，前面的stat已经做了
	//如果攻击者给MobileSubstrate改名，但是原理都是通过DYLD_INSERT_LIBRARIES注入动态库
	//那么可以，检测当前程序运行的环境变量
	char *env = getenv("DYLD_INSERT_LIBRARIES");
	if (env != NULL) {
		jailbroken = YES;
	}
	
	return jailbroken;
}


@end

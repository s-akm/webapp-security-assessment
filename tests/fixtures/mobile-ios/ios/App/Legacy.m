#import <Foundation/Foundation.h>

// 架空の題材
void rememberPassword(NSString *password) {
  [[NSUserDefaults standardUserDefaults] setObject:password forKey:@"userPassword"];
}

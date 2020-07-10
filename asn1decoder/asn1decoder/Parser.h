//
//  Parser.h
//  asn1decoder
//
//  Created by lovecode666 on 2020/7/9.
//  Copyright © 2020 mll<coleflowersma#gmail.com> All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface Parser : NSObject

- (instancetype)initWithPath:(NSString *)path;
- (BOOL)decode;
- (NSDictionary *)getDec;

@end

NS_ASSUME_NONNULL_END

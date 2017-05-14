---
layout: post
title: Shell Learning - 001 - 特殊字符
---

### 注释

shell脚本中用`#`作注释标识, `#`之后的为注释, 不会被执行.

``` shell
	#This is comment
```

`#`可以插入到管道中, 不影响最终结果.

``` shell
	echo "ABCDEF" |\
	#A embedded comment
	grep "BC"
```

在有些命令中`#`并不是注释

``` shell
	echo ${PATH#*:}
	echo $(( 2#10101 ))
```

### 命令分隔符

shell中命令分隔符为`;`, 用来分隔一行中的多个命令, 后面需要添加一个`空格`

``` shell
	if [[ -x $0 ]]; then echo "executable"; done
	#             ^^                      ^^
```

### case中的终结符号(Terminator)

case中每个判断用`;;`来终止, 相当于`break`, 会终止case语句.  
`;;&`会继续后面的判断, 即执行完当前case之后继续判断之后的case.  
`;&`会直接执行后一条语句, 不进行条件判断.  
`;;&`和`;&`需要`bash version 4.0+`

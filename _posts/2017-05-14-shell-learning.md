---
layout: post
title: Shell Learning - 001 - 基础部分
---

### 注释

shell脚本中用``#``作注释标识, ``#``之后的为注释, 不会被执行.
		#This is comment
  
``#``可以插入到管道中, 不影响最终结果.
		echo "ABCDEF" |\
		#A embedded comment
		grep BC

在有些命令中``#``并不是注释
		echo ${PATH#*:}
		echo $(( 2#10101 ))

### 命令分隔符

shell中命令分隔符为``;``, 用来分隔一行中的多个命令
		if [[ -x $0 ]]; then echo "executable"; done
		#			  ^						  ^


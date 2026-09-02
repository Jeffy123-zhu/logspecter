"""支持 ``python -m logspecter``。

必须保留 ``__main__`` 守卫：Windows / macOS 默认使用 spawn 启动子进程，
子进程会重新导入入口模块，没有守卫会导致递归启动。
"""

from __future__ import annotations

from logspecter.cli import main

if __name__ == "__main__":
    main()

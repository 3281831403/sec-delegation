跨服务调用改成票据委托之后，被委托方能以用户身份访问全部资源，委托范围形同虚设：不检查可委托标志，任何票据都能再委托；范围求并集而不是取交集，委托范围被扩大；请求未声明范围时默认继承父票据全部范围；链长度用大于而不是大于等于，允许跳数多一；链中重复服务不去重，同一服务可重复出现；时间窗只校验起点，过期票据被接受；时间窗允许起点等于终点，零长度窗口通过；签发委托票据时链不追加当前服务，链断裂不可审计；策略校验不检查是否允许范围扩大；批量校验复用链状态，第二个请求沿用第一个请求的转发链。deleg/ticket.py 是核心，tests/test_ticket.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

    python -m pytest tests -q

初始状态恰好为 15 failed，且 15 个失败全部是 NotImplementedError。修好 src/deleg/ticket.py 后应变为 15 passed。

## 字段表

| 字段 | 值 |
| --- | --- |
| 方向 | 安全 |
| 类型 | 漏洞检测与攻防 |
| 任务 | Bugfix |
| 环境 | Python 3, pytest |
| 依赖 | 无外部依赖 |

## tests 不可修改

tests/test_ticket.py 与 tests/conftest.py 是验收标准，不可修改。只能修改 src/deleg/ticket.py。

tests/test_ticket.py 共 15 条测试：前 10 条分别对应题面中的 10 个缺陷，后 5 条覆盖合法委托且范围收窄、不可委托的票据被拒、范围扩大被拒、转发链超限被拒、两批独立校验与单独校验相同。

## src 布局

    sec-delegation/
      README.md
      pyproject.toml
      tests/conftest.py
      tests/test_ticket.py
      src/deleg/__init__.py
      src/deleg/ticket.py

src/deleg/ticket.py 是唯一实现文件，恰好 8 个桩，全部 raise NotImplementedError：

1. parse_ticket：解析主体、服务、范围、标志、转发链、签发时间。
2. flag_ok：票据必须显式标记可委托，否则不能出委托票据。
3. scope_narrow：委托范围必须是原范围子集。
4. chain_ok：转发链长度与重复服务检查。
5. time_ok：时间窗两端含且不允许零长度。
6. issue_delegated：签发委托票据，链长度加一。
7. validate_policy：返回策略问题列表。
8. ticket_batch：批量校验，各请求独立。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |


1\.

detect() 接收文档列表，不是单个 RetrievedChunk。

因为一次 Retrieval 本来就可能返回多个 chunk，模块需要对这一批检索结果进行白名单、投毒和相关性检查。接口暂定：



**Python:**

detect(query: str, documents: list\[RetrievedChunk])

\#documents 里的每一个元素统一是一个 RetrievedChunk



2\.

有source ，并设为必填字段。

因为你的白名单判断依赖来源，所以我这边会保证进入你模块之前，每个 RetrievedChunk 都有 source。如果上游检索器没有提供来源，就不应该伪造一个，而是标成 unknown，由你的模块按未知来源处理。

&#x20;

3\.

有score ，但要明确它是“检索相关性分数”，不是安全风险分数。

每个 RetrievedChunk 会有一个 score，表示 Retriever 返回的相关性/相似度分数。你可以把它作为投毒检测的一个输入特征。

你最后输出的 risk\_score 则是你的安全检测结果，这两个不要混在一起：

\#chunk.score       = 检索相关性分数

\#risk\_score        = 安全风险分数



4\.

metadata 第一版不强制 timestamp、tenant 这些业务字段。

V1 先把真正需要联调的字段定下来。每个 RetrievedChunk 的必填字段暂定为：



**Python:**

chunk\_id

content

source

score

metadata

\#metadata 本身保证存在，但允许是空字典 {}。timestamp、tenant 暂时都作为可选字段；以后真实场景需要多租户或者时效性检测时再增加.



5\.

query 单独作为参数传，不塞进 RetrievedChunk。

最终接口:



**Python:**

detect(

&#x20;   query: str,

&#x20;   documents: list\[RetrievedChunk]

)



\#query 我这边传给你。你可以直接做 NLI / query-document 相关性过滤。Query 属于这一次请求的全局信息，同一批所有 chunk 共用，没有必要在每一个 RetrievedChunk 里重复保存。



\#**RetrievedChunk结构体:**



**Python:**



from dataclasses import dataclass, field

from typing import Any, Dict





@dataclass

class RetrievedChunk:

&#x20;   chunk\_id: str

&#x20;   content: str

&#x20;   source: str

&#x20;   score: float

&#x20;   metadata: Dict\[str, Any] = field(

&#x20;       default\_factory=dict

&#x20;   )



最终你收到的belike：



**Python:**



query = "什么是 RAG？"



documents = \[

&#x20;   RetrievedChunk(

&#x20;       chunk\_id="chunk\_001",

&#x20;       content="RAG 是检索增强生成技术……",

&#x20;       source="knowledge\_base\_01",

&#x20;       score=0.91,

&#x20;       metadata={

&#x20;           "timestamp": "2026-09-21"

&#x20;       }

&#x20;   ),



&#x20;   RetrievedChunk(

&#x20;       chunk\_id="chunk\_002",

&#x20;       content="另一段检索内容……",

&#x20;       source="unknown",

&#x20;       score=0.78,

&#x20;       metadata={}

&#x20;   )

]



你需要实现的belike：



**Python:**



def detect(

&#x20;   query: str,

&#x20;   documents: list\[RetrievedChunk]

):

&#x20;   # 1. source → 白名单检查

&#x20;   # 2. score/content → 投毒检测

&#x20;   # 3. query + content → NLI 相关性检测

&#x20;   # 4. 最后输出检测结果

&#x20;   ...






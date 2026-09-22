# test_env.py
import sys
print(f"1. Python 版本: {sys.version}") # 确认是 3.10.x

try:
    import langchain
    print(f"2. LangChain 版本: {langchain.__version__}")
except ImportError:
    print("2. 报错：LangChain 未安装！")

try:
    import chromadb
    print(f"3. ChromaDB 版本: {chromadb.__version__}")
except ImportError:
    print("3. 报错：ChromaDB 未安装！")

try:
    import trulens
    # TruLens 的版本获取方式可能不同，这里简单判断导入
    print("4. TruLens 导入成功")
except ImportError:
    print("4. 报错：TruLens 未安装！")

# 测试 Llama 3.1 8B 是否能用
import openai

# 注意：把 api_key 换成你重新生成的真实 Key，不要带任何其他字符
client = openai.OpenAI(
    api_key="6bb76f12-a8e8-4bce-b42a-e241c037b968", 
    base_url="https://api.scaleway.ai/v1"  # Scaleway 的固定地址
)

try:
    response = client.chat.completions.create(
        model="llama-3.1-8b-instruct", # Scaleway 上的 Llama 3.1 8B 名称
        messages=[
            {"role": "user", "content": "你好，请用一句话回复我。"}
        ],
        max_tokens=50
    )
    print("✅ Scaleway API 调用成功！回复内容：")
    print(response.choices[0].message.content)
except Exception as e:
    print(f"❌ API 调用失败，错误信息: {e}")
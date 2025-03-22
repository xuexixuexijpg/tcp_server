import os
import subprocess

def compile_proto():
    proto_path = "../plugins/proto"
    os.makedirs(proto_path, exist_ok=True)

    # 使用完整路径
    protoc_path = r"E:\developer_tools\protoc-29.4-win64\bin\protoc.exe"  # 替换为你的实际路径

    try:
        result = subprocess.run([
            protoc_path,
            f"--proto_path={proto_path}",
            f"--python_out={proto_path}",
            os.path.join(proto_path, "message.proto")
        ], check=True, capture_output=True, text=True)

        print("Proto文件编译完成")
        return True
    except Exception as e:
        print(f"编译失败: {str(e)}")
        return False

if __name__ == "__main__":
    compile_proto()
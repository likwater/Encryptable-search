import secrets
import string
import timeit
import unittest
from functions import encrypt_key, x_k, find  # 假设这些函数在 functions 模块中

class TestFunctions(unittest.TestCase):
    def test_encrypt_key(self):
        number_of_executions = 1000  # 每次执行的次数

        def run_encrypt_key():
            # 生成随机关键词，长度在1到45字节之间
            keyword_length = secrets.randbelow(45) + 1
            keyword = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(keyword_length))

            # 生成随机密码，长度在1到20字节之间
            password_length = secrets.randbelow(20) + 1
            password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(password_length))

            # 调试信息
            # print(f"Generated keyword: {keyword}, length: {len(keyword)}")
            # print(f"Generated password: {password}, length: {len(password)}")

            C_i = encrypt_key(keyword, password)

            # 添加断言以验证结果
            self.assertIsNotNone(C_i)  # 示例断言，确保 C_i 不为 None

        # 使用 timeit 测量 run_encrypt_key 的执行时间
        execution_time = timeit.timeit(run_encrypt_key, number=number_of_executions)
        average_time_per_call = execution_time / number_of_executions

        # 打印结果
        print(f"\n执行 {number_of_executions} 次 encrypt_key 函数的总时间: {execution_time} 秒")
        print(f"每次执行的平均时间: {average_time_per_call} 秒")

    def test_search_keyword_performance(self):
        number_of_keywords = 1000  # 关键词对的数量
        number_of_executions = 1  # 每次执行的次数
        password = "test_password"

        # 生成随机关键词对
        keywords = [''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(secrets.randbelow(45) + 1)) for _ in range(number_of_keywords)]

        # 建立索引
        dicts = {}
        encrypted_file_name = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        for keyword in keywords:
            C_i = encrypt_key(keyword, password)
            dicts[C_i.hex()] = encrypted_file_name

        def search_keyword(keyword):
            x, k = x_k(keyword, password)
            for i, _ in dicts.items():
                if find(x, k, bytes.fromhex(i)):
                    pass

        # 使用 timeit 测量 search_keyword 的执行时间
        total_time = 0
        for keyword in keywords:
            time_taken = timeit.timeit(lambda: search_keyword(keyword), number=number_of_executions)
            total_time += time_taken

        average_time_per_call = total_time / number_of_keywords

        # 打印结果
        print(f"\n执行 {number_of_keywords} 次 search_keyword 函数的总时间: {total_time} 秒")
        print(f"每次执行的平均时间: {average_time_per_call} 秒")

if __name__ == '__main__':
    # 创建一个测试套件
    suite = unittest.TestSuite()
    suite.addTest(TestFunctions('test_encrypt_key'))
    suite.addTest(TestFunctions('test_search_keyword_performance'))

    # 创建一个测试运行器并设置详细级别
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)




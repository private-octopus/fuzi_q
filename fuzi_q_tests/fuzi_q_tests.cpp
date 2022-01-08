#include "pch.h"
#include "CppUnitTest.h"
#include "fuzi_q_tests.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace fuziqtests
{
	TEST_CLASS(fuziqtests)
	{
	public:
		
		TEST_METHOD(basic)
		{
			int ret = fuzi_q_basic_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(basic_client)
		{
			int ret = fuzi_q_basic_client_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(icid_table)
		{
			int ret = icid_table_test();

			Assert::AreEqual(ret, 0);
		}
	};
}

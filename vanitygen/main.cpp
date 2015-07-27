#include "selftests.h"
#include "nemaddress.h"
#include "utils.h"

#include "KeyPair.h"
#include "KeyGenerator.h"

#include "cppformat/format.h"
#include "leanmean/optionparser.h"

#include <algorithm>
#include <filesystem>
#include <memory>
#include <regex>
#include <string>

#include <memory.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>

// just to have fancy colors
#include <Windows.h>

#define info(strfmt, ...) do { fmt::print(" [.] "); fmt::print(strfmt, __VA_ARGS__); fmt::print("\n"); } while(0)

class KeyPrinter
{
public:
	KeyPrinter(const KeyGenerator::Key& key, bool reversed = false) :
		m_key(key),
		m_reversed(reversed)
	{ }

	friend std::ostream& operator<<(std::ostream &os, const KeyPrinter &self) {
		fmt::MemoryWriter out;
		if (self.m_reversed) {
			for (int i = 31; i >= 0; --i) {
				out.write("{:02x}", self.m_key[i]);
			}
		} else {
			for (size_t i = 0; i < 32; ++i) {
				out.write("{:02x}", self.m_key[i]);
			}
		}
		
		return os << out.c_str();
	}
private:
	const KeyGenerator::Key& m_key;
	bool m_reversed;
};

void runGenerator(const std::string& needle) {
	KeyGenerator keyGenerator;
	info("searching for: {}", needle);

	char address[42];
	uint64_t c = 0;
	time_t start = time(0);
	bool printedStatusLine = false;

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
	
	while (true)
	{
		KeyPair keyPair{ keyGenerator };
		
		calculateAddress(keyPair.getPublicKey().data(), 32, address);
		c++;

		if (!(c % 1047)) {
			time_t end = time(0);
			fprintf(stdout, "\r%10lld keys % 8.2f keys per sec", c, c / (double)(end - start)); fflush(stdout);
			printedStatusLine = true;
		}

		const char* pos = strstr(address, needle.c_str());
		if (pos!= nullptr) {
			if (printedStatusLine) fmt::print("\n");
			// NOTE: we need to print the private key reversed to be compatible with NIS/NCC
			fmt::print("priv: {}", KeyPrinter(keyPair.getPrivateKey(), true));
			fmt::print("\npub : {}", KeyPrinter(keyPair.getPublicKey()));
			printf("%.*s", pos-address, address);

			SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_GREEN);
			printf("%.*s", needle.size(), pos);
			SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);

			printf("%s\n", pos + needle.size());
			printedStatusLine = false;
		}
	}
}

bool verifyLine(const std::string& line) {
	std::regex e("^: ([a-f0-9]+) : ([a-f0-9]+) : ([a-f0-9]+) : ([A-Z2-7]+)$");
	std::smatch sm;
	std::regex_match(line, sm, e);
	
	std::array<uint8_t, 32> privateKey;
	std::array<uint8_t, 32> expectedPublicKey;
	char address[42];
	const std::string& expectedAddress = sm[4];

	inputStringToPrivateKey(sm[1], privateKey.data());
	inputStringToPublicKey(sm[3], expectedPublicKey.data());
	
	KeyPair keyPair{ privateKey };
	calculateAddress(keyPair.getPublicKey().data(), 32, address);
	
	if (memcmp(expectedPublicKey.data(), keyPair.getPublicKey().data(), keyPair.getPublicKey().size()) ||
		expectedAddress != address) {
		fmt::print("\nERROR\n");
		fmt::print("input private key: {}\n", sm[1]);
		fmt::print("      private key: {}\n", KeyPrinter(keyPair.getPrivateKey(), true));

		fmt::print("expected public key: {}\n", KeyPrinter(expectedPublicKey));
		fmt::print("  actual public key: {}\n", KeyPrinter(keyPair.getPublicKey()));

		fmt::print("expected address: {}\n", expectedAddress);
		fmt::print("  actual address: {}\n", address);
		return false;
	}
	return true;
}

void runTestsOnFile(const std::string& filename) {	
	std::ifstream inputFile(filename);

	uint64_t c = 0;
	forLineInFile(inputFile, [&c](const std::string& line) {
		if (!verifyLine(line)) {
			return;
		}

		c++;

		if (!(c % 513)) {
			fmt::print("\r{:10d} tested keys", c);
		}
	});	

	fmt::print("\n{:10d} TEST keys and addresses: OK!\n", c);
}

void printUsage()
{
	fmt::print(R"(
Usage: 
	vanitygen.exe <string-to-search>
)");
}

static option::ArgStatus argIsFile(const option::Option& opt, bool msg)
{
	using std::tr2::sys::exists;
	using std::tr2::sys::path;

	if (msg) {
		if (opt.arg == 0 || ::strlen(opt.arg) == 0 || !exists(path(opt.arg))) {
			fmt::print(" ERROR: cannot open file: {}", opt.arg);
			return option::ARG_ILLEGAL;
		}
	}

	return option::ArgStatus::ARG_OK;
}

enum  optionIndex { Unknown_Flag, Usage, Test_File, Skip_Self_Test };
const option::Descriptor usage[] =
{
	{ Unknown_Flag, 0, "", "", option::Arg::None, "USAGE: example [options]\n\nOptions:" },
	{ Usage, 0, "", "help", option::Arg::None, "  --help  \tPrint usage and exit." },
	{ Test_File, 0, "", "test-file", argIsFile, "  --test-file <file> \tConducts test on an intput file. " },
	{ Skip_Self_Test, 0, "", "skip-self-test", option::Arg::None, "  --skip-self-test  \tSkip self test." },
	{ Unknown_Flag, 0, "", "", option::Arg::None, R"(
EXAMPLES:
  vanitygen.exe foo
  vanitygen.exe --test-file testkeys.dat
  vanitygen.exe --skip-self-test bar
)" },
	{ 0, 0, 0, 0, 0, 0 }
};

static unsigned char base32[] = "234567ABCDEFGHIJKLMNOPQRSTUVWXYZ";

void usageHelper(const char* str, int size) {
	printf("%.*s", size, str);
}

int main(int argc, char** argv) {
	
	argc -= (argc > 0);
	argv += (argc > 0);
	
	option::Stats  stats(usage, argc, argv);

	option::Option *options = new option::Option[stats.options_max];
	option::Option *buffer = new option::Option[stats.buffer_max];
	option::Parser parse(usage, argc, argv, options, buffer);

	if (parse.error())
		return 1;

	if (options[Usage] || argc == 0) {
		option::printUsage(&usageHelper, usage);
		return 0;
	}

	if (options[Skip_Self_Test]) {
	} else if (!selfTest()) {
		return -3;
	}

	if (options[Test_File]) {
		runTestsOnFile(options[Test_File].arg);
		return 0;
	}

	if (parse.nonOptionsCount()) {
		std::string s = parse.nonOption(0);
		std::transform(s.begin(), s.end(), s.begin(), ::toupper);

		for (auto ch : s) {
			if (!std::binary_search(base32, base32 + _countof(base32), ch)) {
				fmt::print("Invalid character: {}, does not occur in base32", ch);
				return -2;
			}
		}

		runGenerator(s);
	}

	return 0;
}

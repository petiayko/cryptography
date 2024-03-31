#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>
#include <numeric>
#include <set>
#include <string>
#include <vector>
#include <unordered_map>

#define RL 0.75
#define alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define alphabet_size 26

struct Key {
    // Структура "Ключ", имеет два поля - множитель и величина сдвига
    explicit Key(
            size_t alpha = 0,
            size_t k = 0) noexcept: alpha(alpha), k(k) {}

    explicit Key(const std::pair<size_t, size_t> &key) {
        alpha = key.first;
        k = key.second;
    }

    [[nodiscard]] std::string to_string() const noexcept {
        return "alpha=" + std::to_string(alpha) + " " + "k=" + std::to_string(k);
    }

    size_t alpha;
    size_t k;
};

// Класс "Аффинный шифр". Имеет публичные методы "зашифровать", "расшифровать"
class AffineCipher {
public:
    explicit AffineCipher(const Key &key) {
        if (!key.alpha) {
            throw std::runtime_error{"Alpha should be positive"};
        }
        _alphabet = alphabet;
        if (std::gcd(key.alpha, _alphabet.size()) != 1) {
            throw std::runtime_error{"Alphabet size and alpha should be coprime numbers"};
        }
        _key = key;
    }

    AffineCipher(const size_t alpha, const size_t k) {
        if (!alpha) {
            throw std::runtime_error{"Alpha should be positive"};
        }
        _alphabet = alphabet;
        if (std::gcd(alpha, _alphabet.size()) != 1) {
            throw std::runtime_error{"Alphabet size and alpha should be coprime numbers"};
        }
        _key = Key(alpha, k);
    }

    [[nodiscard]] std::string encode(const std::string &text) const {
        std::string cipher_text;
        for (char ch: text) {
            if (_alphabet.find(ch) == std::string::npos) {
                throw std::runtime_error{"Unexpected symbol in text: " + std::string(1, ch)};
            }
            cipher_text += _alphabet[_encode(ch)];
        }
        return cipher_text;
    }

    [[nodiscard]] std::string decode(const std::string &cipher_text) const {
        std::string text;
        for (char ch: cipher_text) {
            if (_alphabet.find(ch) == std::string::npos) {
                throw std::runtime_error{"Unexpected symbol in ciphertext: " + std::string(1, ch)};
            }
            text += _alphabet[_decode(ch)];
        }
        return text;
    }

private:
    std::string _alphabet;
    Key _key;

    [[nodiscard]] inline int _encode(const char ch) const noexcept {
        return (_key.alpha * int(ch - 'A') + _key.k) % _alphabet.size();
    }

    [[nodiscard]] inline int _decode(const char ch) const noexcept {
        size_t ord = _alphabet.size();
        return (_opposite(_key.alpha, ord) * (int(ch - 'A') + (ord - _key.k))) % ord;
    }

    [[nodiscard]] int _opposite(const int a, const int m) const noexcept {
        if (a == 1) {
            return 1;
        }
        return (1 - _opposite(m % a, a) * m) / a + m;
    }
};

[[nodiscard]] inline std::unordered_map<size_t, std::set<std::string>> init_gram_library(const size_t max_size) {
    if (max_size < 1) {
        throw std::runtime_error{"Meaningless action"};
    }
    using set = std::set<std::string>;
    using map = std::unordered_map<size_t, set>;

    map library;
    std::string word;
    for (size_t i = 1; i <= max_size; i++) {
        library[i] = set();
        std::ifstream library_file(
                R"(C:\Users\minme\Desktop\Affine cipher\data\library_)" + std::to_string(i) + "-gram.txt");
        if (!library_file.is_open()) {
            throw std::runtime_error{"Unable to open file library_" + std::to_string(i) + "-gram.txt"};
        }
        while (library_file.good()) {
            library_file >> word;
            library[i].insert(word);
        }
    }

    return library;
}


int main() {
    const std::string cipher_text = "BXWMFFGZWEGRXWJGSMBURWIFQIZIMHRXMVWBGESKVSBGBKBGIZEGRXWJCXWJWWMEXHWBBWJ"
                                    "GZMZMHRXMVWBGSQMRRWNBIGBSZKQWJGEWAKGTMHWZBWZEJURBWNKSGZOMSGQRHWQMBXWQMB"
                                    "GEMHFKZEBGIZMZNEIZTWJBWNVMEYBIMHWBBWJBXWFIJQKHMKSWNQWMZSBXMBWMEXHWBBWJW"
                                    "ZEJURBSBIIZWIBXWJHWBBWJMZNVMEYMOMGZQWMZGZOBXWEGRXWJGSWSSWZBGMHHUMSBMZNM"
                                    "JNSKVSBGBKBGIZEGRXWJCGBXMJKHWOITWJZGZOCXGEXHWBBWJOIWSBICXGEXMSSKEXGBXMS"
                                    "BXWCWMYZWSSWSIFMHHSKVSBGBKBGIZEGRXWJSWMEXHWBBWJGSWZEGRXWJWNCGBXBXWFKZEB"
                                    "GIZBXWEGRXWJSRJGQMJUCWMYZWSSEIQWSFJIQBXWFMEBBXMBGFBXWEJURBMZMHUSBEMZNGS"
                                    "EITWJVUQWMZSIFFJWAKWZEUMZMHUSGSVJKBWFIJEWOKWSSGZOIJIBXWJCGSWBXWRHMGZBWL"
                                    "BIFBCIEGRXWJBWLBEXMJMEBWJSBXWZBXWYWUEMZVWIVBMGZWNVUSIHTGZOMSGQKHBMZWIKS"
                                    "WAKMBGIZSGZEWCWYZICMMZNQMJWJWHMBGTWHURJGQWBXGSEMZVWKSWNBIJMRGNHUNGSEMJN"
                                    "QMZUFMHSWYWUSGZMZMKBIQMBWNSUSBWQBXWSMQWBURWIFBJMZSFIJQMBGIZKSWNGZMFFGZW"
                                    "EGRXWJSGSKSWNGZHGZWMJEIZOJKWZBGMHOWZWJMBIJSMBURWIFRSWKNIJMZNIQZKQVWJOWZ"
                                    "WJMBIJBXGSOWZWJMBIJGSZIBMEJURBIOJMRXGEMHHUSWEKJWRSWKNIJMZNIQZKQVWJOWZWJ"
                                    "MBIJFIJBXWSMQWJWMSIZBXMBBXWMFFGZWEGRXWJGSZIBSWEKJW";

    //const auto library = init_gram_library(15);
    std::vector<Key> possible_keys;
    for (size_t alpha = 1; alpha < alphabet_size; alpha++) {
        if (std::gcd(alpha, alphabet_size) != 1) {
            continue;
        }
        for (size_t k = 0; k < alphabet_size; k++) {
            possible_keys.emplace_back(alpha, k);
        }
    }

    for (const auto& key : possible_keys) {
        auto cipher = AffineCipher(key);
        auto decoded_text = cipher.decode(cipher_text.substr(0, 10));
        std::cout << key.to_string() << '\t' << decoded_text << std::endl;
    }
    std::cout << std::endl;

    size_t chosen_alpha;
    size_t chosen_k;

    std::cout << "Enter alpha you choose:";
    std::cin >> chosen_alpha;
    std::cout << std::endl;
    std::cout << "Enter k you choose:";
    std::cin >> chosen_k;
    std::cout << std::endl;

    auto cipher = AffineCipher(chosen_alpha, chosen_k);
    auto decoded_text = cipher.decode(cipher_text);
    std::cout << "Decoded text: " << decoded_text << std::endl;

    /*
    const size_t u_distance = std::ceil(
            std::log2(possible_keys.size()) / (RL * std::log2(alphabet_size)));
    const auto library = init_gram_library(3 * u_distance);

    for (size_t length = 2; length <= u_distance; length++) {
        auto cipher_subtext = cipher_text.substr(0, length);
        std::cout << "Trying for the first " << length << " symbols: " << cipher_subtext << std::endl;
        for (auto it = possible_keys.begin(); it != possible_keys.end();) {
            auto cipher = AffineCipher(*it);
            auto decoded_text = cipher.decode(cipher_subtext);
            if (library.at(length).find(decoded_text) == library.at(length).end()) {
                std::cout << "\tTo remove: " << it->to_string() << std::endl;
                possible_keys.erase(it);
            } else {
                it++;
            }
        }
        std::cout << std::endl;
    }
    std::cout << "Left:" << std::endl;
    for (const auto parameter: possible_keys) {
        std::cout << "\t" << parameter.to_string() << std::endl;
    }
    std::cout << std::endl;

    for (size_t length = 2; length <= 2 * u_distance; length++) {
        auto cipher_subtext = cipher_text.substr(u_distance, length);
        std::cout << "Trying for " << length << " symbols: " << cipher_subtext << std::endl;
        for (auto it = possible_keys.begin(); it != possible_keys.end();) {
            auto cipher = AffineCipher(*it);
            auto decoded_text = cipher.decode(cipher_subtext);
            if (library.at(length).find(decoded_text) == library.at(length).end()) {
                std::cout << "\tTo remove: " << it->to_string() << std::endl;
                possible_keys.erase(it);
            } else {
                it++;
            }
        }
        std::cout << std::endl;
    }
    std::cout << "Left:" << std::endl;
    for (const auto parameter: possible_keys) {
        std::cout << "\t" << parameter.to_string() << std::endl;
    }
    std::cout << std::endl;

    if (possible_keys.size() != 1) {
        throw std::runtime_error{"Decryption failed"};
    }
    std::cout << "Key for this cipher is: " << possible_keys.front().to_string() << std::endl;
    auto cipher = AffineCipher(possible_keys.front());
    std::cout << "Decrypted text:\n" << cipher.decode(cipher_text) << std::endl;
*/
    return 0;
}

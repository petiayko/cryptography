#include <algorithm>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

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
        // метод шифрования
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
        // метод расшифрования
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
        // метод зашифрования одного символа, основываясь на численном представлении тип char
        return (_key.alpha * int(ch - 'A') + _key.k) % _alphabet.size();
    }

    [[nodiscard]] inline int _decode(const char ch) const noexcept {
        // метод расшифрования одного символа, основываясь на численном представлении тип char
        size_t ord = _alphabet.size();
        return (_opposite(_key.alpha, ord) * (int(ch - 'A') + (ord - _key.k))) % ord;
    }

    [[nodiscard]] int _opposite(const int a, const int m) const noexcept {
        // метод получения обратного по модулю для использования в методе расшифрования
        if (a == 1) {
            return 1;
        }
        return (1 - _opposite(m % a, a) * m) / a + m;
    }
};

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

    // получение всех ключей - таких двоек alpha и k, где alpha взаимнопросто с мощностью рабочего алфавита
    std::vector<Key> possible_keys;
    for (size_t alpha = 1; alpha < alphabet_size; alpha++) {
        if (std::gcd(alpha, alphabet_size) != 1) {
            continue;
        }
        for (size_t k = 0; k < alphabet_size; k++) {
            possible_keys.emplace_back(alpha, k);
        }
    }

    // расшифрование 10 первых символов шифртекста с помощью каждого клбюча
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

    // вывод дешифрованного текста на основе выбранного пользователем ключа
    auto cipher = AffineCipher(chosen_alpha, chosen_k);
    auto decoded_text = cipher.decode(cipher_text);
    std::cout << "Decoded text: " << decoded_text << std::endl;

    return 0;
}

#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <stdexcept>
#include <limits>
#include <vector>
#include <iterator>

#define MAX_ATTEMPTS 100000

using namespace std;

template <class keyType>
class Crypto {
    private:
        char flag;
        keyType key;
        string inputFile;
        string outputFile;
        int argc;
        char **argv;
        ifstream fin;
        ofstream fout;
        vector<string> input;
        vector<string> output;
        vector<string> dictionary;
        keyType defaultKey;
        int numWords;
        bool (*validateKey)(const keyType);
        keyType (*keyGen_)(keyType);
        vector<string> (*encoder)(const vector<string>, const keyType);
        vector<string> (*decoder)(const vector<string>, const keyType);

    public:
        static const char ENCODE = 'c';
        static const char DECODE = 'd';

        Crypto(bool (*validateKey)(const keyType), vector<string> (*encoder)(const vector<string> file, const keyType), vector<string> (*decoder)(const vector<string> file, const keyType), keyType (*keyGen)(keyType), string dictionaryFile, keyType defaultKey) {
            this->validateKey = validateKey;
            this->encoder = encoder;
            this->decoder = decoder;
            this->keyGen_ = keyGen;
            this->defaultKey = defaultKey;

            string term;
            fin.open(dictionaryFile);
            
            while (fin >> term)
                dictionary.push_back(term);
            
            fin.close();
        }

        void setArgs(int argc, char **argv) {
            if (!argv[1]) throw invalid_argument("Utilizzare il flag -c per codificare o il flag -d per decodificare");
            flag = argv[1][1];

            if (flag == 'h') {
                cout << "La sintassi del comando e'\nnome_programma -<flag> [nome_file_input] [nome_file_output]" << endl;
                cout << "Dove <flag> va sostituito con il carattere 'c' se si desidera codificare l'input, o 'd' se lo si desidera decodificare." << endl;
                cout << "I nomi dei file di input e di output non devono essere piu' lunghi di 20 caratteri e sono opzionali." << endl;
                cout << "Nel caso in cui non venissero specificati, il file di input sara' 'input.txt', e il file di output sara' 'output.txt'." << endl; 
            } else if (flag != ENCODE && flag != DECODE) throw invalid_argument("Il flag specificato non e' valido. Lanciare il comando con il flag -h per maggiori dettagli.");

            if (argc >= 2 && argv[2]) {
                if (strlen(argv[2]) > 20) 
                    throw invalid_argument("Il nome del file di input e' troppo lungo: utilizzare un nome lungo meno di 21 caratteri. Lanciare il comando con il flag -h per maggiori informazioni.");
            } else {
                inputFile = "input.txt";
            }

            if (argc >= 3 && argv[3] && string(argv[3]).find("TERM_PROGRAM") == string::npos) {
                if (strlen(argv[3]) > 20)
                    throw invalid_argument("Il nome del file di output e' troppo lungo: utilizzare un nome lungo meno di 21 caratteri. Lanciare il comando con il flag -h per maggiori informazioni.");
            } else {
                outputFile = "output.txt";
            }

            fin.open(inputFile);

            string line;
            int wordCount = 0;
            while (getline(fin, line)) {
                istringstream iss(line);
                vector<string> words((istream_iterator<string>(iss)), istream_iterator<string>());
                    
                for (vector<string>::iterator curWord = words.begin(); curWord != words.end(); ++curWord)
                    wordCount++;
                
                input.push_back(line);
            }

            this->numWords = wordCount;

            fin.close();

            fout.open(outputFile);
        }

        char getFlag() {
            return flag;
        }

        void getKeyFromConsole() {
            bool validInput;
            do {
                validInput = true;
                try {
                    cout << "Inserisci la chiave di cifratura: " << endl;
                    cin >> key;
                    if (cin.fail() || !validateKey(key)) {
                        cin.clear();
                        cin.ignore(numeric_limits<streamsize>::max(),'\n');
                        throw "Il tipo o il formato della chiave inserita non e' corretto. Riprovare.";
                    }
                } catch (const char *exception) {
                    validInput = false;
                    cout << exception << endl;
                }
            } while (!validInput);
        }

        void encode() {
            vector<string> output = encoder(input, key);
            for (vector<string>::iterator row = output.begin(); row != output.end(); ++row)
                fout << *row << endl;
        }

        keyType keyGen() {
            return keyGen_(defaultKey);
        }

        keyType keyGen(keyType key) {
            return keyGen_(key);
        }

        void decode() {
            int wordCount, maxWords = 0, attempts = 0;
            keyType foundKey;

            vector<string> output;
            keyType curKey = keyGen();

            try {
                while (attempts <= MAX_ATTEMPTS) {
                    output = decoder(input, curKey);
                    wordCount = 0;

                    for (vector<string>::iterator row = output.begin(); row != output.end(); ++row) {
                        istringstream iss(*row);
                        vector<string> words((istream_iterator<string>(iss)), istream_iterator<string>());
                        
                        for (vector<string>::iterator curWord = words.begin(); curWord != words.end(); ++curWord) {
                            if (find(dictionary.begin(), dictionary.end(), *curWord) != dictionary.end())
                                wordCount++;
                        }
                    }

                    if (wordCount > maxWords) {
                        foundKey = curKey;
                        maxWords = wordCount;
                    }

                    if (wordCount > this->numWords * 50 / 100)
                        break;

                    curKey = keyGen(curKey);
                }
            } catch (int e) {
                if (e != 1) cout << "Error " << e << endl;
            }

            output = decoder(input, foundKey);

            for (vector<string>::iterator row = output.begin(); row != output.end(); ++row)
                fout << *row << endl;
            
            if (attempts > MAX_ATTEMPTS)
                cout << "La funzione per generare le chiavi per la decodifica ha raggiunto il massimo di " << MAX_ATTEMPTS << " tentativi. L'output fornito corrisponde alla migliore soluzione trovata." << endl;
            else
                cout << "Chiave trovata: " << foundKey << endl;
        }
};
using System;

namespace AlgorithmTests
{
    /*
     * Autorzy: Szymon Kasperek, Mateusz Kozieł.
     * Klasa HC128 pozwala na generowanie strumienia szyfrującego oraz na szyfrowanie wiadomości przy zadanych wcześniej
     * wartościach klucza oraz wektora inicjalizującego.
     */
    public class HC128
    {   
        /*
         * Licznik używany przy generowaniu keystream'a.
         */
        UInt32 count = 0;
        /*
         * Tablica uint przechowująca wartości wektora inicjalizującego.
         */
        UInt32[] IV = new uint[4];
        /*
         * Tablica uint przechowująca wartości klucza.
         */
        UInt32[] K = new uint[4];
        /*
         * Tablica W jest tablicą wielkości 1280, w której wykonywane są operacje mające na celu stworzenie
         * strumienia szyfrującego.
         */
        UInt32[] W = new uint[1280];
        /*
         * Tablica P jest tablicą wielkości 512, w której wykonywane są operacje mające na celu stworzenie
         * strumienia szyfrującego.
         */
        UInt32[] P = new uint[512];
        /*
         * Tablica Q jest tablicą wielkości 512, w której wykonywane są operacje mające na celu stworzenie
         * strumienia szyfrującego.
         */
        UInt32[] Q = new uint[512];
        
        public static void Main(string[] args)
        {
            HC128 hc128 = new HC128("00400000000000000000000000000000",
                "00000000000000000000000000000000");
            byte[] keystream = hc128.encryptDecrypt("00000000000000000000000000000000");
            Console.WriteLine(BitConverter.ToString(keystream).Replace("-", ""));
        }
        /*
         * Konstruktor objektów klasy HC128. Wpisuje wartości podanego klucza oraz wektora inicjalizującego do
         * odpowienich tablic.
         */
        public HC128(string keyHex, string ivHex)
        {
            byte[] key = StringToByteArray(keyHex);
            byte[] iv = StringToByteArray(ivHex);
            K[0] = BitConverter.ToUInt32(key, 0);
            K[1] = BitConverter.ToUInt32(key, 4);
            K[2] = BitConverter.ToUInt32(key, 8);
            K[3] = BitConverter.ToUInt32(key, 12);
            IV[0] = BitConverter.ToUInt32(iv, 0);
            IV[1] = BitConverter.ToUInt32(iv, 4);
            IV[2] = BitConverter.ToUInt32(iv, 8);
            IV[3] = BitConverter.ToUInt32(iv, 12);
        }
        /*
         * Funkcja inicjalizująca. Rozszerza klucz oraz wektor inicjalizujący do tablic P, Q oraz W.
         * Szczegółowy opis działań na tablicach przedstawiony jest w dokumentacji szyfru HC128 w sekcji 2.2.
         */
        private void initState()
        {
            for (int i = 0; i < 8; i++)
            {
                W[i] = K[i % 4];
            }
            for (int i = 8; i < 16; i++)
            {
                W[i] = IV[(i-8) % 4];
            }
            for (int i = 16; i < 1280; i++)
            {
                W[i] = (uint) (F2(W[i - 2]) + W[i - 7] + F1(W[i - 15]) + W[i - 16] + i);
            }
            for (int i = 0; i < 512; i++)
            {
                P[i] = W[i + 256];
                Q[i] = W[i + 768];
            }
            for (int i = 0; i < 512; i++)
            {
                P[i] = (P[i] +
                        G1(P[subMod512((uint) i, 3)], P[subMod512((uint) i, 10)], P[subMod512((uint) i, 511)]))
                       ^ H1(P[subMod512((uint) i, 12)]);
            }
            for (int i = 0; i < 512; i++)
            {
                Q[i] = (Q[i] +
                        G2(Q[subMod512((uint) i, 3)], Q[subMod512((uint) i, 10)], Q[subMod512((uint) i, 511)]))
                       ^ H2(Q[subMod512((uint) i, 12)]);
            }
        }
        /*
         * Funkcja przedstawiająca jeden krok generowania strumienia szyfrującego. Szczegółowy jej opis przedstawiony
         * jest w dokumentacji szyfru w sekcji 2.3.
         */
        private uint generateKeystreamUint()
        {
            uint j = count % 512;
            uint result;
            if (count % 1024 < 512)
            {
                P[j] = P[j] +
                       G1(P[subMod512(j, 3)], P[subMod512(j, 10)], P[subMod512(j, 511)]);

                result = H1(P[subMod512(j, 12)]) ^ P[j];
            }
            else
            {
                Q[j] = Q[j] +
                       G2(Q[subMod512(j, 3)], Q[subMod512(j, 10)], Q[subMod512(j, 511)]);

                result = H2(Q[subMod512(j, 12)]) ^ Q[j];
            }
            count++;
            return result;
        }
        /*
         * Funkcja szyfrująca zadaną wiadomość przedstawioną w formacie heksadecymalnym.
         */
        public byte[] encryptDecrypt(string dataHex)
        {
            byte[] data = StringToByteArray(dataHex);
            initState();
            byte[] keyStream = new byte[data.Length + data.Length % 4];
            for (int i = 0; i < keyStream.Length / 4; i++)
            {
                byte[] keyB = BitConverter.GetBytes(generateKeystreamUint());
                Buffer.BlockCopy(keyB, 0, keyStream, i * 4, 4);
            }

            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) result[i] = (byte) (data[i] ^ keyStream[i]);
            return result;
        }
        /*
         * Funkcja pomocnicza realizująca działanie odejmowania modulo 512.
         */
        private uint subMod512(uint a, uint b)
        {
            return (a - b) % 512;
        }
        /*
         * Funkcja pomocnicza przedstaiona w dokumentacji pod nazwą f1. Używana do generowania odpowiednich wartości
         * w tablicach P,Q,W.
         */
        private uint F1(uint x)
        {
            return RollRight(x, 7) ^ RollRight(x, 18) ^ (x >> 3);
        }
        /*
         * Funkcja pomocnicza przedstaiona w dokumentacji pod nazwą f2. Używana do generowania odpowiednich wartości
         * w tablicach P,Q,W.
         */
        private uint F2(uint x)
        {
            return RollRight(x, 17) ^ RollRight(x, 19) ^ (x >> 10);
        }
        /*
         * Funkcja pomocnicza przedstaiona w dokumentacji pod nazwą g1. Używana do generowania odpowiednich wartości
         * w tablicach P,Q,W.
         */
        private uint G1(uint x, uint y, uint z)
        {
            return (RollRight(x, 10) ^ RollRight(z, 23)) + RollRight(y, 8);
        }
        /*
         * Funkcja pomocnicza przedstaiona w dokumentacji pod nazwą g2. Używana do generowania odpowiednich wartości
         * w tablicach P,Q,W.
         */
        private uint G2(uint x, uint y, uint z)
        {
            return (RollLeft(x, 10) ^ RollLeft(z, 23)) + RollLeft(y, 8);
        }
        /*
         * Funkcja pomocnicza przedstaiona w dokumentacji pod nazwą h1. Używana do generowania odpowiednich wartości
         * w tablicach P,Q,W.
         */
        private uint H1(uint x)
        {
            return Q[(byte) x] + Q[256 + (byte) (x >> 16)];
        }
        /*
         * Funkcja pomocnicza przedstaiona w dokumentacji pod nazwą h2. Używana do generowania odpowiednich wartości
         * w tablicach P,Q,W.
         */
        private uint H2(uint x)
        {
            return P[(byte) x] + P[256 + (byte) (x >> 16)];
        }
        /*
         * Funkcja pomocnicza realizująca bitową funkcję rotate right. W dokumentacji przedstawiana jako >>>
         */
        private uint RollRight(uint x, int n)
        {
            return (x >> n) ^ (x << (32 - n));
        }
        /*
         * Funkcja pomocnicza realizująca bitową funkcję rotate right. W dokumentacji przedstawiana jako <<<
         */
        private uint RollLeft(uint x, int n)
        {
            return (x << n) ^ (x >> (32 - n));
        }
        /*
         * Funkcja pomocnicza pozwalająca przedstawić String jako tablicę bajtów.
         */
        private static byte[] StringToByteArray(string hex)
        {
            var numberChars = hex.Length;
            var bytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}
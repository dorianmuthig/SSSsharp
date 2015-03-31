using Gnu.Getopt;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SSSsharp
{
    class Program
    {
        static string VERSION = "0.5";
        static string RANDOM_SOURCE = "RNGCryptoServiceProvider";
        static int MAXDEGREE = 1024;
        static int MAXTOKENLEN = 128;
        static int MAXLINELEN
        {
            get
            {
                return (MAXTOKENLEN + 1 + 10 + 1 + MAXDEGREE / 4 + 10);
            }
        }

        /* coefficients of some irreducible polynomials over GF(2) */
        static readonly byte[] irred_coeff = {
            4,3,1,5,3,1,4,3,1,7,3,2,5,4,3,5,3,2,7,4,2,4,3,1,10,9,3,9,4,2,7,6,2,10,9,
            6,4,3,1,5,4,3,4,3,1,7,2,1,5,3,2,7,4,2,6,3,2,5,3,2,15,3,2,11,3,2,9,8,7,7,
            2,1,5,3,2,9,3,1,7,3,1,9,8,3,9,4,2,8,5,3,15,14,10,10,5,2,9,6,2,9,3,2,9,5,
            2,11,10,1,7,3,2,11,2,1,9,7,4,4,3,1,8,3,1,7,4,1,7,2,1,13,11,6,5,3,2,7,3,2,
            8,7,5,12,3,2,13,10,6,5,3,2,5,3,2,9,5,2,9,7,2,13,4,3,4,3,1,11,6,4,18,9,6,
            19,18,13,11,3,2,15,9,6,4,3,1,16,5,2,15,14,6,8,5,2,15,11,2,11,6,2,7,5,3,8,
            3,1,19,16,9,11,9,6,15,7,6,13,4,3,14,13,3,13,6,3,9,5,2,19,13,6,19,10,3,11,
            6,5,9,2,1,14,3,2,13,3,1,7,5,4,11,9,8,11,6,5,23,16,9,19,14,6,23,10,2,8,3,
            2,5,4,3,9,6,4,4,3,2,13,8,6,13,11,1,13,10,3,11,6,5,19,17,4,15,14,7,13,9,6,
            9,7,3,9,7,1,14,3,2,11,8,2,11,6,4,13,5,2,11,5,1,11,4,1,19,10,3,21,10,6,13,
            3,1,15,7,5,19,18,10,7,5,3,12,7,2,7,5,1,14,9,6,10,3,2,15,13,12,12,11,9,16,
            9,7,12,9,3,9,5,2,17,10,6,24,9,3,17,15,13,5,4,3,19,17,8,15,6,3,19,6,1 };

        static bool opt_showversion = false;
        static bool opt_help = false;
        static bool opt_quiet = false;
        static bool opt_QUIET = false;
        static bool opt_hex = false;
        static bool opt_diffusion = true;
        static int opt_security = 0;
        static int opt_threshold = -1;
        static int opt_number = -1;
        static string opt_token = null;

        static int degree;
        static BigInteger poly;
        static RNGCryptoServiceProvider cprng;

        static void Main(string[] args)
        {
            string name = Process.GetCurrentProcess().MainModule.FileName;
            int i;

            opt_help = (args.Length == 0);
            Getopt getopt = new Getopt(name, args, "vDhqQxs:t:n:w:");

            while ((i = getopt.getopt()) != -1)
            {
                switch (i)
                {
                    case 'v': opt_showversion = true; break;
                    case 'h': opt_help = true; break;
                    case 'q': opt_quiet = true; break;
                    case 'Q': opt_QUIET = opt_quiet = true; break;
                    case 'x': opt_hex = true; break;
                    case 's': opt_security = Convert.ToInt32(getopt.Optarg); break;
                    case 't': opt_threshold = Convert.ToInt32(getopt.Optarg); break;
                    case 'n': opt_number = Convert.ToInt32(getopt.Optarg); break;
                    case 'w': opt_token = getopt.Optarg; break;
                    case 'D': opt_diffusion = false; break;
                    default:
                        Environment.Exit(1);
                        break;
                }
            }
            if (!opt_help && (args.Length != getopt.Optind))
            {
                fatal("invalid argument");
            }

            if (name == null)
            {
                name = Path.GetFileName(Assembly.GetEntryAssembly().Location);
            }

            if (name.Contains("split"))
            {
                if (opt_help || opt_showversion)
                {
                    Console.WriteLine(string.Concat("Split secrets using Shamir's Secret Sharing Scheme.", Environment.NewLine,
                                                    Environment.NewLine,
                                                    "ssss-split -t threshold -n shares [-w token] [-s level]",
                                                    " [-x] [-q] [-Q] [-D] [-v]")
                     );
                    if (opt_showversion)
                    {
                        Console.WriteLine(string.Concat(Environment.NewLine, "Version: ", VERSION));
                    }
                    Environment.Exit(0);
                }

                if (opt_threshold < 2)
                {
                    fatal("invalid parameters: invalid threshold value");
                }

                if (opt_number < opt_threshold)
                {
                    fatal("invalid parameters: number of shares smaller than threshold");
                }

                if (opt_security != 0 && !field_size_valid(opt_security))
                {
                    fatal("invalid parameters: invalid security level");
                }

                if (!string.IsNullOrEmpty(opt_token) && (opt_token.Length > MAXTOKENLEN))
                {
                    fatal("invalid parameters: token too long");
                }

                split();
            }
            else
            {
                if (opt_help || opt_showversion)
                {
                    Console.WriteLine(string.Concat("Combine shares using Shamir's Secret Sharing Scheme.", Environment.NewLine,
                                                    Environment.NewLine,
                                                    "ssss-combine -t threshold [-x] [-q] [-Q] [-D] [-v]"));
                    if (opt_showversion)
                    {
                        Console.WriteLine(string.Concat(Environment.NewLine, "Version: ", VERSION));
                    }
                    Environment.Exit(0);
                }

                if (opt_threshold < 2)
                {
                    fatal("invalid parameters: invalid threshold value");
                }

                combine();
            }
            return;
        }

        /* Prompt for a secret, generate shares for it */

        static void split()
        {
            int fmt_len;
            BigInteger x;
            BigInteger y;
            BigInteger[] coeff = new BigInteger[opt_threshold];
            string buf = string.Empty;
            int deg, i;
            for (fmt_len = 1, i = opt_number; i >= 10; i /= 10, fmt_len++) ;
            if (!opt_quiet)
            {
                Console.Write("Generating shares using a ({0},{1}) scheme with ", opt_threshold, opt_number);
                if (opt_security > 0)
                {
                    Console.Write("a {0} bit", opt_security);
                }
                else
                {
                    Console.Write("dynamic");
                }
                Console.Write(string.Concat(" security level.", Environment.NewLine));

                deg = opt_security > 0 ? opt_security : MAXDEGREE;
                Console.Error.Write("Enter the secret, ");
                if (opt_hex)
                {
                    Console.Error.Write("as most {0} hex digits: ", deg / 4);
                }
                else
                {
                    Console.Error.Write("at most {0} ASCII characters: ", deg / 8);
                }
            }
            try
            {
                buf = Console.ReadLine();
                buf = buf.Split('\n')[0].Split('\r')[0];
                if (string.IsNullOrEmpty(buf))
                {
                    fatal("No secret supplied");
                }
            }
            catch (Exception e)
            {
                fatal("I/O error while reading secret");
            }

            if (opt_security == 0)
            {
                opt_security = opt_hex ? (4 * ((buf.Length + 1) & ~1)) : (8 * buf.Length);
                if (!field_size_valid(opt_security))
                {
                    fatal("security level invalid (secret too long?)");
                }
                if (!opt_quiet)
                {
                    Console.Error.WriteLine("Using a {0} bit security level.", opt_security);
                }
            }

            field_init(opt_security);

            coeff[0] = BigInteger.Zero;
            coeff[0] = field_import(buf, opt_hex);

            if (opt_diffusion)
            {
                if (degree >= 64)
                {
                    coeff[0] = encode_mpz(coeff[0], encdec.ENCODE);
                }
                else
                {
                    warning("security level too small for the diffusion layer");
                }
            }

            cprng_init();
            for (i = 1; i < opt_threshold; i++)
            {
                coeff[i] = BigInteger.Zero;
                coeff[i] = cprng_read();
            }
            cprng_deinit();

            x = BigInteger.Zero;
            y = BigInteger.Zero;
            for (i = 0; i < opt_number; i++)
            {
                x = i + 1;
                y = horner(opt_threshold, x, coeff);
                if (!string.IsNullOrEmpty(opt_token))
                {
                    Console.Write("{0}-", opt_token);
                }
                string fmtString = string.Empty;
                for (int j = 0; j < fmt_len; j++)
                {
                    fmtString = string.Concat(fmtString, "0");
                }
                Console.Write("{0}-", (i + 1).ToString(fmtString));
                field_print(Console.OpenStandardOutput(), y, true);
            }
            x = new BigInteger();
            y = new BigInteger();

            for (i = 0; i < opt_threshold; i++)
            {
                coeff[i] = new BigInteger();
            }
            field_deinit();
        }

        /* Prompt for shares, calculate the secret */

        static void combine()
        {
            BigInteger[,] A = new BigInteger[opt_threshold, opt_threshold];
                    BigInteger[] y = new BigInteger[opt_threshold];
                    BigInteger x;
            string buf = string.Empty;
            string a = string.Empty;
            string b = string.Empty;
            int i = 0;
            int j = 0;
            int s = 0;

            x = BigInteger.Zero;
            if (!opt_quiet)
            {
                Console.Write("Enter {0} shares separated by newlines:{1}", opt_threshold, Environment.NewLine);
            }
            for (i = 0; i < opt_threshold; i++)
            {
                if (!opt_quiet)
                {
                    Console.Write("Share [{0}/{1}]: ", i + 1, opt_threshold);
                }

                try
                {
                    buf = Console.ReadLine();
                    buf = buf.Split('\n')[0].Split('\r')[0];
                    if (string.IsNullOrEmpty(buf))
                    {
                        fatal("No shares supplied");
                    }
                }
                catch (Exception e)
                {
                    fatal("I/O error while reading shares");
                }

                if (!buf.Contains('-'))
                {
                    Debugger.Launch();
                    fatal("invalid syntax");
                }
                if (buf.Split('-').Length > 2)
                {
                    b = buf.Split('-')[2];
                    a = buf.Split('-')[1];
                }
                else
                {
                    b = buf.Split('-')[1];
                    a = buf.Split('-')[0];
                }

                if (s < 1)
                {
                    s = 4 * b.Length;
                    if (!field_size_valid(s))
                    {
                        fatal("share has illegal length");
                    }
                    field_init(s);
                }
                else if (s != 4 * b.Length)
                {
                    fatal("shares have different security levels");
                }
                try
                {
                    j = Convert.ToInt32(a);
                }
                catch (Exception e)
                {
                    fatal("invalid share");
                }               
                x = j;
                A[opt_threshold - 1, i] = BigInteger.One;
                for (j = opt_threshold - 2; j >= 0; j--)
                {
                    A[j, i] = BigInteger.Zero;
                    A[j,i] = field_mult(A[j + 1, i], x);
                }
                y[i] = BigInteger.Zero;
                y[i] = field_import(b, true);
                x = field_mult(x, A[0, i]);
                y[i] = field_add(y[i], x);
            }
            x = new BigInteger();
            try
            {
                A = restore_secret(opt_threshold, A, y);
            }
            catch (Exception e)
            {
                fatal("shares inconsistent. Perhaps a single share was used twice");
            }
            if (opt_diffusion)
            {
                if (degree >= 64)
                {
                    encode_mpz(y[opt_threshold - 1], encdec.DECODE);
                }
                else
                {
                    warning("security level too small for the diffusion layer");
                }
            }

            if (!opt_quiet)
            {
                Console.Error.Write("Resulting secret: ");
            }
            field_print(Console.OpenStandardError(), y[opt_threshold - 1], opt_hex);

            for (i = 0; i < opt_threshold; i++)
            {
                for (j = 0; j < opt_threshold; j++)
                {
                    A[i, j] = new BigInteger();
                }
                y[i] = new BigInteger();
            }
            field_deinit();
        }

        /* emergency abort and warning functions */
        static void fatal(string message)
        {
            Console.Error.WriteLine(string.Concat("FATAL: ", message, "."));
            Environment.Exit(1);
        }

        static void warning(string message)
        {
            if (!opt_QUIET)
            {
                Console.Error.WriteLine(string.Concat("WARNING: ", message, "."));
            }
        }

        static bool field_size_valid(int deg)
        {
            return ((deg >= 8) && (deg <= MAXDEGREE) && (deg % 8 == 0));
        }
        /* initialize 'poly' to a bitfield representing the coefficients of an
           irreducible polynomial of degree 'deg' */

        static void field_init(int deg)
        {
            Debug.Assert(field_size_valid(deg));
            poly = BigInteger.Zero;
            poly = poly.SetBit(deg);
            poly = poly.SetBit(irred_coeff[3 * (deg / 8 - 1) + 0]);
            poly = poly.SetBit(irred_coeff[3 * (deg / 8 - 1) + 1]);
            poly = poly.SetBit(irred_coeff[3 * (deg / 8 - 1) + 2]);
            poly = poly.SetBit(0);
            degree = deg;
        }
        static void field_deinit()
        {
            poly = new BigInteger();
        }

        /* I/O routines for GF(2^deg) field elements */

        static BigInteger field_import(string s, bool hexmode)
        {
            BigInteger x = new BigInteger();
            if (hexmode)
            {
                if (s.Length > degree / 4)
                {
                    fatal("input string too long");
                }
                if (s.Length < degree / 4)
                {
                    warning("input string too short, adding null padding on the left");
                }
                bool parseBigInt = true;
                try
                {
                    x = s.hexStringToBigInt();
                }
                catch (Exception e)
                {
                    parseBigInt = false;
                }
                if (!parseBigInt || BigInteger.Compare(x, BigInteger.Zero) < 0)
                {
                    Debugger.Launch();
                    fatal("invalid syntax");
                }
                return x;
            }
            else
            {
                int i;
                bool warn = false;
                if (s.Length > degree / 8)
                    fatal("input string too long");
                for (i = s.Length - 1; i >= 0; i--)
                {
                    warn = warn || (s[i] < 32) || (s[i] >= 127);
                }
                if (warn)
                {
                    warning("binary data detected, use -x mode instead"); // Unicode ???
                }
                byte[] stringBytes = Encoding.UTF8.GetBytes(s);         //  ⌝
                Array.Reverse(stringBytes);                             //  |
                Array.Resize(ref stringBytes, stringBytes.Length + 1);  //  |
                stringBytes[stringBytes.Length - 1] = 0x00;             //  ↓
                return new BigInteger(stringBytes);                     // not sure if that's right, though
            }
        }
        enum encdec { ENCODE, DECODE };

        /* a 64 bit pseudo random permutation (based on the XTEA cipher) */

        static uint[] encipher_block(uint[] v)
        {
            uint sum = 0, delta = 0x9E3779B9;
            int i;
            for (i = 0; i < 32; i++)
            {
                v[0] += (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ sum;
                sum += delta;
                v[1] += (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ sum;
            }
            return v;
        }

        static uint[] decipher_block(uint[] v)
        {
            uint sum = 0xC6EF3720, delta = 0x9E3779B9;
            int i;
            for (i = 0; i < 32; i++)
            {
                v[1] -= ((v[0] << 4 ^ v[0] >> 5) + v[0]) ^ sum;
                sum -= delta;
                v[0] -= ((v[1] << 4 ^ v[1] >> 5) + v[1]) ^ sum;
            }
            return v;
        }

        static uint[] encode_slice(uint[] data, int idx, int len, Func<uint[], uint[]> process_block)
        {
            uint[] v = new uint[2];
            int i;
            for (i = 0; i < 2; i++)
            {
                v[i] = data[(idx + 4 * i) % len] << 24 |
                data[(idx + 4 * i + 1) % len] << 16 |
                data[(idx + 4 * i + 2) % len] << 8 | data[(idx + 4 * i + 3) % len];
            }
            v = process_block(v);
            for (i = 0; i < 2; i++)
            {
                data[(idx + 4 * i + 0) % len] = v[i] >> 24;
                data[(idx + 4 * i + 1) % len] = (v[i] >> 16) & 0xff;
                data[(idx + 4 * i + 2) % len] = (v[i] >> 8) & 0xff;
                data[(idx + 4 * i + 3) % len] = v[i] & 0xff;
            }
            return data;
        }
        static BigInteger encode_mpz(BigInteger x, encdec encdecmode)
        {
            uint[] v = new uint[(MAXDEGREE + 8) / 16 * 2];
            int i;
            byte[] numberBytes = x.ToByteArray();
            Buffer.BlockCopy(numberBytes, 0, v, 0, numberBytes.Length);
            Array.Reverse(v);
            //v = x.ToUintArray(2, Extensions.Order.Reverse);
            //Array.Resize(ref v, (MAXDEGREE + 8) / 16 * 2);
            if (degree % 16 == 8)
            {
                v[degree / 8 - 1] = v[degree / 8];
            }
            if (encdecmode == encdec.ENCODE)             /* 40 rounds are more than enough!*/
            {
                for (i = 0; i < 40 * ((int)degree / 8); i += 2)
                {
                    encode_slice(v, i, degree / 8, encipher_block);
                }
            }
            else
            {
                for (i = 40 * (degree / 8) - 2; i >= 0; i -= 2)
                {
                    encode_slice(v, i, degree / 8, decipher_block);
                }
            }
            if (degree % 16 == 8)
            {
                v[degree / 8] = v[degree / 8 - 1];
                v[degree / 8 - 1] = 0;
            }
            //x = v.ToBigInt((degree + 8) / 16, 2, Extensions.Order.Reverse);
            Array.Reverse(v);
            Buffer.BlockCopy(v, 0, numberBytes, 0, numberBytes.Length / 4);
            x = new BigInteger(numberBytes);
            Debug.Assert(x.BitLength() <= degree);

            return x;
        }
        static void cprng_init()
        {
            try
            {
                cprng = new RNGCryptoServiceProvider();
            }
            catch (Exception e)
            {
                fatal(string.Concat("couldn't open ", RANDOM_SOURCE));
            }
        }

        static void cprng_deinit()
        {
            try
            {
                cprng.Dispose();
            }
            catch (Exception e)
            {
                fatal(string.Concat("couldn't close ", RANDOM_SOURCE));
            }
        }
        static BigInteger cprng_read()
        {
            byte[] buf = new byte[MAXDEGREE / 8];
            BigInteger x;            
            try
            {
                cprng.GetBytes(buf);
            }
            catch (Exception e)
            {
                cprng.Dispose();
                fatal(string.Concat("couldn't read from ", RANDOM_SOURCE));
            }
            Array.Resize(ref buf, degree / 8); // + 1);
            //buf[buf.Length - 1] = 0x00;
            x = new BigInteger(buf);
            if (x < 0)
            {
                x = BigInteger.Negate(x);
            }
            return x;
        }
        /* evaluate polynomials efficiently */

        static BigInteger horner(int n, BigInteger x, BigInteger[] coeff)
        {
            int i;
            BigInteger y = x;
            for (i = n - 1; i > 0; i--)
            {
                y = field_add(y, coeff[i]);
                y = field_mult(y, x);
            }
            y = field_add(y, coeff[0]);
            return y;
        }

        /* basic field arithmetic in GF(2^deg) */

        static BigInteger field_add(BigInteger x, BigInteger y)
        {
            BigInteger z = x.Xor(y);
            return z;
        }

        static BigInteger field_mult(BigInteger x, BigInteger y)
        {
            BigInteger b;
            BigInteger z = new BigInteger();
            int i;
            Debug.Assert(z != y);
            b = x;
            if (y.GetBit(0))
            {
                z = b;
            }
            else
            {
                z = BigInteger.Zero;
            }
            for (i = 1; i < degree; i++)
            {
                b = b.LeftShift(1);
                if (b.GetBit(degree))
                {
                    b = b.Xor(poly);
                }
                if (y.GetBit(i))
                {
                    z = z.Xor(b);
                }
            }
            b = new BigInteger();
            return z;
        }

        static BigInteger field_invert(BigInteger x)
        {
            BigInteger u, v, g, h, z;
            int i;
            Debug.Assert(BigInteger.Compare(x, BigInteger.Zero) != 0);
            u = x;
            v = poly;
            g = BigInteger.Zero;
            z = BigInteger.One;
            h = new BigInteger();
            while (BigInteger.Compare(u, BigInteger.One) != 0) // let's do this FOREVER! Like an insane person.
            {
                i = u.BitLength() - v.BitLength();
                if (i < 0)
                {
                    BigInteger temp;
                    temp = v;
                    v = u;
                    u = temp;
                    temp = z;
                    z = g;
                    g = temp;
                    i = -i;
                }
                h = v.LeftShift(i);
                u = u.Xor(h);
                h = g.LeftShift(i);
                z = z.Xor(h);
            }
            u = new BigInteger(); 
            v = new BigInteger(); 
            g = new BigInteger(); 
            h = new BigInteger();
            return z;
        }

        static void field_print(Stream stream, BigInteger x, bool hexmode)
        {
            
            if (hexmode)
            {
                int i;
                for (i = 0; i < (degree / 4 - x.ToHexString().Length); i++)
                {
                    stream.Write("0");
                }
                stream.Write(x.ToHexString());
                stream.Write(Environment.NewLine);
            }
            else
            {
                byte[] buf = new byte[MAXDEGREE / 8 + 1];
                int t;
                int i;
                bool printable, warn = false;
                buf = x.ToByteArray();
                t = buf.Length;
                Array.Reverse(buf);
                for (i = 0; i < t; i++)
                {
                    printable = (buf[i] >= 32) && (buf[i] < 127);
                    warn = warn || !printable;
                    stream.Write(printable ? Encoding.UTF8.GetString(buf, i, 1) : ".");
                }
                stream.Write(Environment.NewLine);
                if (warn)
                {
                    warning("binary data detected, use -x mode instead");
                }
            }
        }
        /* calculate the secret from a set of shares solving a linear equation system */
        static BigInteger[,] restore_secret(int n, BigInteger[,] AA, BigInteger[] b)
        {
            int i, j, k; 
            bool found;
            BigInteger h = BigInteger.Zero;
            for (i = 0; i < n; i++)
            {
                if (BigInteger.Compare(AA[i, i], BigInteger.Zero) == 0)
                {
                    found = false;
                    for (j = i + 1; j < n; j++)
                    {
                        if (BigInteger.Compare(AA[i, j], BigInteger.Zero) != 0)
                        {
                            found = true;
                            break;
                        }
                    }
                    if (!found)
                    {
                        throw new ArgumentOutOfRangeException("AA, n", AA, "supplied BigInteger array with secrets does not match security threshold");
                    }
                    BigInteger temp;
                    for (k = i; k < n; k++)
                    {
                        temp = AA[k, i];
                        AA[k, i] = AA[k, j];
                        AA[k, j] = temp;
                    }
                    temp = b[i];
                    b[i] = b[j];
                    b[j] = temp;			        
                }
                for (j = i + 1; j < n; j++)
                {
                    if (BigInteger.Compare(AA[i, j], BigInteger.Zero) != 0)
                    {
                        for (k = i + 1; k < n; k++)
                        {
                            h = field_mult(AA[k, i], AA[i, j]);
                            AA[k, j] = field_mult(AA[k, j], AA[i, i]);
                            AA[k, j] = field_add(AA[k, j], h);
                        }
                        h = field_mult(b[i], AA[i, j]);
                        b[j] = field_mult(b[j], AA[i, i]);
                        b[j] = field_add(b[j], h);
                    }
                }
            }
            h = field_invert(AA[n - 1, n - 1]);
            b[n - 1] = field_mult(b[n - 1], h);
            h = new BigInteger();
            return AA;
        }        
    }
    public static class Extensions
    {
        public static BigInteger SetBit(this BigInteger bigNumber, int bitIndex)
        {
            int byteCount = bitIndex / 8;
            byte[] numberAsBytes = bigNumber.ToByteArray();
            if (numberAsBytes.Length < byteCount)
            {
                Array.Resize(ref numberAsBytes, byteCount + 1);
            }
            numberAsBytes = numberAsBytes.SetBit(bitIndex);
            return new BigInteger(numberAsBytes);
        }
        public static BigInteger ClearBit(this BigInteger bigNumber, int bitIndex)
        {
            int byteCount = bitIndex / 8;
            byte[] numberAsBytes = bigNumber.ToByteArray();
            if (numberAsBytes.Length < byteCount)
            {
                Array.Resize(ref numberAsBytes, byteCount + 1);
            }
            numberAsBytes = numberAsBytes.ClearBit(bitIndex);
            return new BigInteger(numberAsBytes);
        }
        public static BigInteger ToggleBit(this BigInteger bigNumber, int bitIndex)
        {
            int byteCount = bitIndex / 8;
            byte[] numberAsBytes = bigNumber.ToByteArray();
            if (numberAsBytes.Length < byteCount)
            {
                Array.Resize(ref numberAsBytes, byteCount + 1);
            }
            numberAsBytes = numberAsBytes.ToggleBit(bitIndex);
            return new BigInteger(numberAsBytes);
        }
        public static bool GetBit(this BigInteger bigNumber, int bitIndex)
        {
            bool result = false;
            int byteCount = bitIndex / 8;
            byte[] numberAsBytes = bigNumber.ToByteArray();
            if (numberAsBytes.Length - 1 >= byteCount)
            {
                result = numberAsBytes.GetBit(bitIndex);
            }
            return result;
        }
        public static int BitLength(this BigInteger bigNumber)
        {
            int bitLength = 0;
            //BigInteger two = new BigInteger(2);            

            //while (bigNumber % 2 == 0)
            //{
            //    bigNumber = BigInteger.Divide(bigNumber, two);
            //    bitLength++;
            //}
            do
            {
                bitLength++;
            } while ((bigNumber >>= 1) != 0);
            return BigInteger.Compare(bigNumber, BigInteger.Zero) != 0 ? bitLength : 0;
        }
        public static BigInteger LeftShift(this BigInteger bigNumber, int bits) // regular bitshift for BigInteger type is broken
        {
            return BigInteger.Pow(BigInteger.Multiply(bigNumber, 2), bits);
        }
        public static BigInteger Xor(this BigInteger bigNumber, BigInteger bigNumber2)
        {
            byte[] bigNumBytes = bigNumber.ToByteArray();
            byte[] bigNum2Bytes = bigNumber2.ToByteArray();
            if (bigNumBytes.Length != bigNum2Bytes.Length)
            {
                if (bigNumBytes.Length > bigNum2Bytes.Length)
                {
                    Array.Resize(ref bigNum2Bytes, bigNumBytes.Length);
                }
                else
                {
                    Array.Resize(ref bigNumBytes, bigNum2Bytes.Length);
                }
            }
            byte[] result = new byte[bigNumBytes.Length];
            for (int i = 0; i < bigNumBytes.Length - 1; i++)
            {
                result[i] = (byte)(bigNumBytes[i] ^ bigNum2Bytes[i]);
            }
            return new BigInteger(result);
        }
        public enum Order : int {
            Normal = 1,
            Reverse = -1
        }
        public static BigInteger ToBigInt(this uint wordData)
        {
            return new uint[1] { wordData }.ToBigInt(1, 1);
        }
        public static BigInteger ToBigInt(this uint[] wordData, int wordCount, int wordSize)
        {
            return wordData.ToBigInt(wordCount, wordSize, Order.Normal);
        }
        public static BigInteger ToBigInt(this uint[] wordData, int wordCount, int wordSize, Order order)
        {
            //int l = wordData.Length;
            //while (l > 0 && wordData[--l] == 0)
            //{
            //    ;
            //}
            //Array.Resize(ref wordData, l + 1);
            if (wordSize > 4)
            {
                throw new ArgumentOutOfRangeException("wordSize", "Cannot be more bytes than size of uint (4 bytes)");
            }
            else if (wordSize < 1)
            {
                throw new ArgumentOutOfRangeException("wordSize", "Cannot be less than one byte");
            }
            byte[] wordBytes = new byte[wordData.Length * 4];
            Buffer.BlockCopy(wordData, 0, wordBytes, 0, wordData.Length);
            uint[] wordArray = new uint[wordBytes.Length / wordSize];
            for (int i = 0; i < wordArray.Length; i++)
            {
                uint[] word = new uint[1];
                Buffer.BlockCopy(wordBytes, i * wordSize, word, 4 - wordSize, wordSize);
                wordArray[i] = word[0];
            }
            if (order == Order.Reverse)
            {
                Array.Reverse(wordArray);
            }
            Array.Resize(ref wordArray, wordCount);
            wordBytes = new byte[wordArray.Length * wordSize];
            for (int i = 0; i < wordArray.Length; i++)
            {
                byte[] word = new byte[4];
                Buffer.BlockCopy(wordArray, i, word, 0, 1);
                Buffer.BlockCopy(word, 4 - wordSize, wordBytes, i * wordSize, wordSize);
            }
            Array.Reverse(wordBytes);
            Array.Resize(ref wordBytes, wordBytes.Length + 1);
            wordBytes[wordBytes.Length - 1] = 0x00;
            return new BigInteger(wordBytes);
        }
        public static uint ToUint(this BigInteger bigNumber)
        {
            if (bigNumber < BigInteger.Zero || bigNumber > uint.MaxValue)
            {
                throw new ArgumentOutOfRangeException("bigNumber");
            }
            return (uint)bigNumber;
        }
        public static uint[] ToUintArray(this BigInteger bigNumber, int wordSize)
        {
            return bigNumber.ToUintArray(wordSize, Order.Normal);
        }
        public static uint[] ToUintArray(this BigInteger bigNumber, int wordSize, Order order)
        {
            if (wordSize > 4)
            {
                throw new ArgumentOutOfRangeException("wordSize", "Cannot be more bytes than size of uint (4 bytes)");
            }
            else if (wordSize < 1)
            {
                throw new ArgumentOutOfRangeException("wordSize", "Cannot be less than one byte");
            }
            byte[] wordBytes = bigNumber.ToByteArray();
            Array.Reverse(wordBytes);
            uint[] wordArray = new uint[wordBytes.Length / wordSize];
            for (int i = 0; i < wordArray.Length; i++)
            {
                uint[] word = new uint[1];
                Buffer.BlockCopy(wordBytes, i * wordSize, word, 4 - wordSize, wordSize);
                wordArray[i] = word[0];
            }
            if (order == Order.Reverse)
            {
                Array.Reverse(wordArray);
            }
            return wordArray;
        }
        public static string ToHexString(this BigInteger bigNumber)
        {
            byte[] bigNumBytes = bigNumber.ToByteArray();
            Array.Reverse(bigNumBytes);
            string bigNumHexString = string.Empty;
            foreach(byte bigNumByte in bigNumBytes)
            {
                string temp = bigNumByte.ToString("X");
                if (temp.Length < 2)
                {
                    temp = string.Concat("0", temp);
                }
                bigNumHexString = string.Concat(bigNumHexString, temp);
            }
            //if (bigNumHexString.StartsWith("00"))
            //{
            //    bigNumHexString = bigNumHexString.Substring(2);
            //}
            return bigNumHexString;
        }
        public static BigInteger hexStringToBigInt(this string hexString)
        {
            byte[] numberBytes;
            foreach (char c in hexString)
            {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                {
                    throw new ArgumentException("Not a valid hexadecimal string", "hexString");
                }
            }
            if (hexString.Length % 2 != 0)
            {
                hexString = string.Concat("0", hexString);
            }
            //hexString = string.Concat("00", hexString);
            numberBytes = new byte[hexString.Length >> 1];
            for (int i = 0; i < hexString.Length >> 1; ++i)
            {
                int value1 = hexString[i << 1];
                value1 = value1 - (value1 < 58 ? 48 : (value1 < 97 ? 55 : 87));
                int value2 = hexString[(i << 1) + 1];
                value2 = value2 - (value2 < 58 ? 48 : (value2 < 97 ? 55 : 87));
                numberBytes[i] = (byte)((value1 << 4) + (value2));
            }
            Array.Reverse(numberBytes);
            return new BigInteger(numberBytes);
        }

        public static byte[] SetBit(this byte[] byteArray, int index, bool value)
        {
            int byteIndex = index / 8;
            int bitIndex = index % 8;
            byte mask = (byte)(1 << bitIndex);
            byteArray[byteIndex] = (byte)(value ? (byteArray[byteIndex] | mask) : (byteArray[byteIndex] & ~mask));
            return byteArray;
        }

        public static byte[] SetBit(this byte[] byteArray, int index)
        {
            int byteIndex = index / 8;
            int bitIndex = index % 8;
            byte mask = (byte)(1 << bitIndex);
            byteArray[byteIndex] = (byte)(byteArray[byteIndex] | mask);
            return byteArray;
        }
        public static byte[] ClearBit(this byte[] byteArray, int index)
        {
            int byteIndex = index / 8;
            int bitIndex = index % 8;
            byte mask = (byte)(1 << bitIndex);
            byteArray[byteIndex] = (byte)(byteArray[byteIndex] & ~mask);
            return byteArray;
        }

        public static byte[] ToggleBit(this byte[] byteArray, int index)
        {
            int byteIndex = index / 8;
            int bitIndex = index % 8;
            byte mask = (byte)(1 << bitIndex);
            byteArray[byteIndex] ^= mask;
            return byteArray;
        }

        public static bool GetBit(this byte[] byteArray, int index)
        {
            int byteIndex = index / 8;
            int bitIndex = index % 8;
            byte mask = (byte)(1 << bitIndex);

            return (byteArray[byteIndex] & mask) != 0;
        }
        public static void Write(this Stream stream, string message)
        {
            byte[] writeBytes = Encoding.UTF8.GetBytes(message);
            stream.Write(writeBytes, 0, writeBytes.Length);
        }
    }
}

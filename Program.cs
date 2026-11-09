/*
 * CajaFuerte_IMartin_Falcó - ACT02 Algoritmo AES
 *
 * Uso:
 *   CajaFuerte cifrar    <fichero_entrada.txt> <fichero_salida.caja> <contraseña>
 *   CajaFuerte descifrar <fichero_salida.caja> <fichero_recuperado> <contraseña>
 *
 * Cifrado con AES-256 en modo GCM. La clave se saca de la contraseña con
 * PBKDF2 (SHA-256, 600.000 iteraciones). La sal y el nonce se generan con
 * RandomNumberGenerator cada vez que se cifra.
 *
 * Formato del fichero .caja:
 *
 *   Bytes 0  - 15   (16 bytes)  sal
 *   Bytes 16 - 27   (12 bytes)  nonce
 *   Bytes 28 - 43   (16 bytes)  tag de autenticación de GCM
 *   Bytes 44 - fin  (N bytes)   texto cifrado
 *
 * En hexadecimal: sal 0x00-0x0F, nonce 0x10-0x1B, tag 0x1C-0x2B y el texto
 * cifrado empieza en 0x2C. El .caja ocupa 44 bytes más que el .txt original.
 */

using System.Security.Cryptography;
using System.Text;

class Program
{
    const int TAM_SAL = 16;
    const int TAM_NONCE = 12;
    const int TAM_TAG = 16;
    const int TAM_CLAVE = 32; // 32 bytes = AES-256
    const int ITERACIONES = 600_000;
    const int TAM_CABECERA = TAM_SAL + TAM_NONCE + TAM_TAG;

    static int Main(string[] args)
    {
        if (args.Length != 4)
        {
            MostrarUso();
            return 1;
        }

        string accion = args[0].ToLower();
        string ficheroEntrada = args[1];
        string ficheroSalida = args[2];
        string contrasena = args[3];

        if (string.IsNullOrEmpty(contrasena))
        {
            Console.WriteLine("ERROR: la contraseña no puede estar vacía.");
            return 1;
        }

        if (!AesGcm.IsSupported)
        {
            Console.WriteLine("ERROR: AES-GCM no está disponible en este equipo.");
            return 1;
        }

        if (accion == "cifrar")
        {
            return Cifrar(ficheroEntrada, ficheroSalida, contrasena);
        }
        else if (accion == "descifrar")
        {
            return Descifrar(ficheroEntrada, ficheroSalida, contrasena);
        }
        else
        {
            MostrarUso();
            return 1;
        }
    }

    static int Cifrar(string ficheroEntrada, string ficheroSalida, string contrasena)
    {
        if (!File.Exists(ficheroEntrada))
        {
            Console.WriteLine("ERROR: no existe el fichero " + ficheroEntrada);
            return 1;
        }
        if (Path.GetExtension(ficheroEntrada).ToLower() != ".txt")
        {
            Console.WriteLine("ERROR: el fichero de entrada tiene que ser un .txt");
            return 1;
        }
        if (Path.GetExtension(ficheroSalida).ToLower() != ".caja")
        {
            Console.WriteLine("ERROR: el fichero de salida tiene que acabar en .caja");
            return 1;
        }

        // Lo leo en bytes para que al descifrar quede igual byte a byte
        byte[] textoPlano = File.ReadAllBytes(ficheroEntrada);

        // Sal y nonce nuevos en cada cifrado
        byte[] sal = RandomNumberGenerator.GetBytes(TAM_SAL);
        byte[] nonce = RandomNumberGenerator.GetBytes(TAM_NONCE);

        byte[] clave = DerivarClave(contrasena, sal);

        byte[] textoCifrado = new byte[textoPlano.Length];
        byte[] tag = new byte[TAM_TAG];

        using (AesGcm aes = new AesGcm(clave, TAM_TAG))
        {
            aes.Encrypt(nonce, textoPlano, textoCifrado, tag);
        }

        CryptographicOperations.ZeroMemory(clave);

        // Orden del fichero: sal, nonce, tag, texto cifrado
        using (FileStream fs = new FileStream(ficheroSalida, FileMode.Create))
        {
            fs.Write(sal, 0, sal.Length);
            fs.Write(nonce, 0, nonce.Length);
            fs.Write(tag, 0, tag.Length);
            fs.Write(textoCifrado, 0, textoCifrado.Length);
        }

        Console.WriteLine("OK: fichero cifrado correctamente -> " + ficheroSalida);
        return 0;
    }

    static int Descifrar(string ficheroEntrada, string ficheroSalida, string contrasena)
    {
        if (!File.Exists(ficheroEntrada))
        {
            Console.WriteLine("ERROR: no existe el fichero " + ficheroEntrada);
            return 1;
        }

        byte[] datos = File.ReadAllBytes(ficheroEntrada);

        if (datos.Length < TAM_CABECERA)
        {
            Console.WriteLine("ERROR: el fichero es demasiado pequeño, no es un .caja válido o está dañado.");
            return 1;
        }

        byte[] sal = new byte[TAM_SAL];
        byte[] nonce = new byte[TAM_NONCE];
        byte[] tag = new byte[TAM_TAG];
        byte[] textoCifrado = new byte[datos.Length - TAM_CABECERA];

        Array.Copy(datos, 0, sal, 0, TAM_SAL);
        Array.Copy(datos, TAM_SAL, nonce, 0, TAM_NONCE);
        Array.Copy(datos, TAM_SAL + TAM_NONCE, tag, 0, TAM_TAG);
        Array.Copy(datos, TAM_CABECERA, textoCifrado, 0, textoCifrado.Length);

        byte[] clave = DerivarClave(contrasena, sal);
        byte[] textoPlano = new byte[textoCifrado.Length];

        // Si el tag no coincide (fichero modificado o contraseña mal),
        // Decrypt lanza la excepción y no se escribe nada
        try
        {
            using (AesGcm aes = new AesGcm(clave, TAM_TAG))
            {
                aes.Decrypt(nonce, textoCifrado, tag, textoPlano);
            }
        }
        catch (AuthenticationTagMismatchException)
        {
            Console.WriteLine("ERROR DE INTEGRIDAD: el fichero ha sido MANIPULADO o la contraseña es INCORRECTA.");
            Console.WriteLine("No se ha descifrado nada y no se ha creado el fichero de salida.");
            return 1;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clave);
        }

        File.WriteAllBytes(ficheroSalida, textoPlano);

        Console.WriteLine("OK: integridad verificada y fichero descifrado -> " + ficheroSalida);
        return 0;
    }

    // PBKDF2 con SHA-256 para pasar de contraseña a clave de 256 bits
    static byte[] DerivarClave(string contrasena, byte[] sal)
    {
        byte[] bytesContrasena = Encoding.UTF8.GetBytes(contrasena);

        byte[] clave = Rfc2898DeriveBytes.Pbkdf2(
            bytesContrasena,
            sal,
            ITERACIONES,
            HashAlgorithmName.SHA256,
            TAM_CLAVE);

        CryptographicOperations.ZeroMemory(bytesContrasena);
        return clave;
    }

    static void MostrarUso()
    {
        Console.WriteLine("Uso:");
        Console.WriteLine("  CajaFuerte cifrar    <fichero_entrada.txt> <fichero_salida.caja> <contraseña>");
        Console.WriteLine("  CajaFuerte descifrar <fichero_salida.caja> <fichero_recuperado> <contraseña>");
    }
}

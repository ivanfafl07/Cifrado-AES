# CajaFuerte_IMartin_Falcó — ACT02 Algoritmo AES (DAM2)

Aplicación de consola en C# (.NET 10) que cifra y descifra ficheros `.txt` con **AES-256-GCM**.
La clave se obtiene de la contraseña con **PBKDF2-SHA256 (600.000 iteraciones)**.

## Cómo se usa

```
CajaFuerte cifrar    <fichero_entrada.txt> <fichero_salida.caja> <contraseña>
CajaFuerte descifrar <fichero_salida.caja> <fichero_recuperado> <contraseña>
```

Desde la carpeta del proyecto (o en Visual Studio: *Ver → Terminal*):

```
dotnet run -- cifrar    ejemplo/prueba.txt ejemplo/prueba.caja "MiContraseña"
dotnet run -- descifrar ejemplo/prueba.caja ejemplo/recuperado.txt "MiContraseña"
```

Si el fichero `.caja` ha sido modificado o la contraseña es incorrecta, el programa muestra
`ERROR DE INTEGRIDAD` y **no crea** el fichero de salida.

## Formato del fichero .caja

| Bytes       | Tamaño   | Contenido                       |
|-------------|----------|---------------------------------|
| 0 – 15      | 16 bytes | Sal (PBKDF2)                    |
| 16 – 27     | 12 bytes | Nonce / IV (AES-GCM)            |
| 28 – 43     | 16 bytes | Tag de autenticación (GCM)      |
| 44 – final  | N bytes  | Texto cifrado                   |

## Fichero para verificar

`ejemplo/secreto.caja` está cifrado con este programa. La contraseña se entrega en un documento aparte.

```
dotnet run -- descifrar ejemplo/secreto.caja ejemplo/secreto_recuperado.txt "<contraseña>"
```

## Pregunta: «Si guardaras la clave de cifrado en el mismo sitio que el fichero cifrado, ¿qué habrías conseguido realmente?»

Nada de seguridad real. Cualquiera que consiga el fichero cifrado consigue también la clave y puede
descifrarlo al momento, así que es como cerrar una caja fuerte y dejar la llave pegada en la puerta.
AES-256 es muy robusto, pero la seguridad del cifrado depende de que la clave sea secreta, no de que
el algoritmo sea secreto (principio de Kerckhoffs). Por eso la clave (o la contraseña) siempre tiene
que guardarse en un sitio distinto y protegido.

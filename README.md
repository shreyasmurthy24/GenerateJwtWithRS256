# GenerateJwtWithRS256
This function app projects helps to generate a JWT with private key input using RS-256 algorithm.
RS-256 algorithm takes only integer value as its parameter, generally 2048, will be passed as an input. When writing code for a company 
that needs OAuth authentication, JWT helps solve the purpose.
If the request is to use RS-256, with a public/private keys, generated for example using OpenSSL, the key is alpha-numeric. Casting is not 
a good idea. To over-come this issue, Nuget manager has a library named Bouncy Castle, whcih helps in converting the alpha-numeric to
interger values, i.e. it converts the value to bytes using the UTF8 encoding. This is an example from the JwtManager.cs class.

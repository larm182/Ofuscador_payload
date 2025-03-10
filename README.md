Ofuscador de Payloads Metasploit

Este es un ofuscador de payloads generado con Metasploit, desarrollado en Python con una interfaz en Tkinter. Su objetivo es aplicar técnicas de ofuscación para evadir antivirus y mejorar la ejecución en entornos controlados.

Características

Múltiples métodos de ofuscación:

Base64

XOR

ROT13

AES

RC4

Blowfish

Inserción de código basura para aumentar la complejidad del payload.

Ejecución en memoria para evitar escritura en disco.

Interfaz gráfica en Tkinter con diseño en tonos azules.

Compatibilidad con Windows (probado en Windows 10).

Exportación del payload ofuscado en un archivo de texto.

Requisitos

Python 3.x

Bibliotecas necesarias (instalar con pip si es necesario):

pip install pycryptodome

Instalación y Uso

Clonar el repositorio:

git clone https://github.com/larm182/Ofuscador_payload.git

cd ofuscador-payloads

Ejecutar el script:

python ofuscador.py

Seleccionar un payload generado con msfvenom.

Elegir el método de ofuscación y configuraciones adicionales.

Guardar el payload ofuscado o ejecutarlo en memoria.

Advertencia

Este software está desarrollado con fines educativos y de investigación en ciberseguridad. El uso indebido de esta herramienta es responsabilidad exclusiva del usuario.

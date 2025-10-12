Guía de Contribución para NetWatcher
¡Gracias por tu interés en contribuir a NetWatcher! Estamos emocionados de recibir ayuda de la comunidad para hacer de esta herramienta educativa un recurso aún mejor.

Cómo Contribuir
Puedes contribuir de varias maneras:

Reportando Bugs: Si encuentras un error, por favor, abre un issue usando la plantilla de "Bug Report".

Sugiriendo Mejoras: ¿Tienes una idea para una nueva función o una mejora? Abre un issue usando la plantilla de "Feature Request".

Escribiendo Código: Si quieres solucionar un bug o implementar una nueva característica, ¡genial! Sigue los pasos a continuación.

Mejorando la Documentación: Si ves algo que no está claro o que podría explicarse mejor, no dudes en proponer cambios.

Proceso de Desarrollo (Pull Requests)
Haz un Fork del Repositorio: Haz clic en el botón "Fork" en la esquina superior derecha de la página del repositorio.

Clona tu Fork:

git clone [https://github.com/tu-usuario/ciberseguridad-netwatcher.git](https://github.com/tu-usuario/ciberseguridad-netwatcher.git)
cd ciberseguridad-netwatcher

Crea una Rama Nueva: Es importante trabajar en una rama separada para cada nueva característica o corrección.

git checkout -b feature/nombre-de-la-caracteristica # Para nuevas funciones
# o
git checkout -b fix/descripcion-del-bug # Para correcciones

Configura tu Entorno de Desarrollo:

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Realiza tus Cambios: Escribe tu código. Asegúrate de seguir las guías de estilo y de añadir comentarios cuando sea necesario.

Añade Pruebas (Tests): Si estás añadiendo una nueva función, por favor, incluye pruebas unitarias que la cubran.

Verifica el Código: Antes de enviar tus cambios, ejecuta el linter y las pruebas para asegurarte de que todo funciona correctamente.

flake8 .
pytest

Haz Commit de tus Cambios: Usa mensajes de commit claros y descriptivos.

git add .
git commit -m "feat: Añade la función de escaneo XYZ"

Sube tus Cambios a tu Fork:

git push origin feature/nombre-de-la-caracteristica

Abre un Pull Request (PR): Ve a la página del repositorio original y verás un botón para abrir un PR desde tu rama. Describe tus cambios claramente en el PR.

Un mantenedor del proyecto revisará tu PR lo antes posible. ¡Gracias por tu contribución!
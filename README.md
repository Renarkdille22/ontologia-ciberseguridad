## Descripción del Proyecto

Esta ontología modela el dominio de la ciberseguridad organizacional utilizando el estándar OWL/RDF. Fue desarrollada en Protégé y validada con el razonador HermiT sin errores lógicos. Permite representar amenazas informáticas, vulnerabilidades, controles de seguridad y sus relaciones dentro de un entorno estructurado.

**Namespace:** `http://www.miOntologia.org/ciberseguridad#`  
**Archivo principal:** `ciberseguridadrss.owl`  
**Repositorio:** https://github.com/Renarkdille22/ontologia-ciberseguridad

## Descripción de la Ontología

Esta ontología modela el dominio de la ciberseguridad organizacional con las siguientes clases principales:

| Clase | Descripción |
|---|---|
| `Activo` | Recurso de valor para la organización que debe ser protegido |
| `Amenaza` | Evento que puede comprometer la confidencialidad, integridad o disponibilidad |
| `Control` | Medida implementada para reducir o eliminar una amenaza |
| `Vulnerabilidad` | Debilidad en un sistema que puede ser explotada |
| `Política` | Conjunto de reglas que guían la gestión de la seguridad |

### Subclases

**Activos:** Base_de_Datos, Servidor_Web, Cuenta_Correo, Dispositivo_Red

**Amenazas:** Phishing, Ransomware, Malware, Ataque_DDoS

**Controles:** Firewall, Antivirus, Cifrado, Autenticacion_Doble_Factor

**Vulnerabilidades:** Vulnerabilidad_Software, Vulnerabilidad_Hardware, Credenciales_Debiles, Configuracion_Incorrecta

**Políticas:** Politica_Acceso, Politica_Contraseñas, Politica_Respaldo

### Propiedades

| Propiedad | Dominio | Rango | Descripción |
|---|---|---|---|
| `afecta` | Amenaza | Activo | Una amenaza afecta a un activo |
| `mitiga` | Control | Amenaza | Un control mitiga una amenaza |
| `protegidoPor` | Activo | Control | Un activo está protegido por un control |
| `requiere` | Política | Control | Una política requiere un control |
| `nivelRiesgo` | Amenaza | Integer | Nivel de riesgo de la amenaza (1-5) |
| `criticidad` | Activo | Integer | Criticidad del activo (1-5) |
| `fechaDeteccion` | Vulnerabilidad | DateTime | Fecha en que se detectó la vulnerabilidad |

### Individuos

| Individuo | Clase | Datos |
|---|---|---|
| `Phishing_Corporativo` | Phishing | nivelRiesgo: 4 |
| `Ransomware_WannaCry` | Ransomware | nivelRiesgo: 5 |
| `BD_Clientes` | Base_de_Datos | criticidad: 5 |
| `Servidor_Web_Principal` | Servidor_Web | criticidad: 5 |
| `Cuenta_Correo_Empresa` | Cuenta_Correo | — |
| `FirewallCisco` | Firewall | — |
| `Antivirus_Norton` | Antivirus | — |
| `2FA_Google` | Autenticacion_Doble_Factor | — |
| `SQL_Injection` | Vulnerabilidad_Software | fechaDeteccion: 2024-01-15 |

---

## Ejemplos de Uso — Consultas SPARQL

### 1. Consultar controles que mitigan una amenaza

```sparql
SELECT ?control WHERE {
    ?control <http://www.miOntologia.org/ciberseguridad#mitiga>
             <http://www.miOntologia.org/ciberseguridad#Phishing_Corporativo> .
}
```

### 2. Consultar todas las amenazas registradas

```sparql
SELECT ?individuo WHERE {
    ?individuo a ?clase .
    ?clase <http://www.w3.org/2000/01/rdf-schema#subClassOf>
           <http://www.miOntologia.org/ciberseguridad#Amenaza> .
}
```

### 3. Consultar activos afectados por una amenaza

```sparql
SELECT ?activo WHERE {
    <http://www.miOntologia.org/ciberseguridad#Phishing_Corporativo>
    <http://www.miOntologia.org/ciberseguridad#afecta> ?activo .
}
```

### 4. Consultar nivel de riesgo de una amenaza

```sparql
SELECT ?riesgo WHERE {
    <http://www.miOntologia.org/ciberseguridad#Ransomware_WannaCry>
    <http://www.miOntologia.org/ciberseguridad#nivelRiesgo> ?riesgo .
}
```

### 5. Consultar todos los activos y su criticidad

```sparql
SELECT ?activo ?criticidad WHERE {
    ?activo a ?clase .
    ?clase <http://www.w3.org/2000/01/rdf-schema#subClassOf>
           <http://www.miOntologia.org/ciberseguridad#Activo> .
    OPTIONAL { ?activo <http://www.miOntologia.org/ciberseguridad#criticidad> ?criticidad }
}
```

---

## Agente Python

El archivo `ejemplos/agente_python.py` implementa un agente inteligente con chatbot
que consulta la ontología mediante SPARQL.

### Requisitos

```bash
pip install owlready2 rdflib
```

### Uso

```bash
python agente_python.py
```

### Funcionalidades del Agente

| Método | Descripción |
|---|---|
| `recomendar(amenaza)` | Retorna controles que mitigan la amenaza |
| `activos_afectados(amenaza)` | Retorna activos que la amenaza compromete |
| `nivel_riesgo(amenaza)` | Retorna el nivel de riesgo (1-5) |
| `listar_amenazas()` | Lista todas las amenazas en la ontología |
| `diagnostico(amenaza)` | Reporte completo de una amenaza |
| `mostrar_relaciones()` | Muestra tripletas del grafo RDF |
| `chatbot()` | Interfaz conversacional para consultas |


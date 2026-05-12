from owlready2 import *
from rdflib import Namespace

onto = get_ontology("https://raw.githubusercontent.com/Renarkdille22/ontologia-ciberseguridad/main/ciberseguridadrss.owl").load()

g = default_world.as_rdflib_graph()

ns = Namespace("http://www.miOntologia.org/ciberseguridad#")

class AgenteCiberseguridad:
    def __init__(self, grafo):
        self.grafo = grafo

    def recomendar(self, amenaza):
        consulta = f"""
        SELECT ?control WHERE {{
            ?control <{ns.mitiga}> <{amenaza}> .
        }}
        """
        return [str(r[0]).split("#")[-1] for r in self.grafo.query(consulta)]

    def mostrar_relaciones(self, limite=10):
        print("=== RELACIONES ENCONTRADAS ===\n")
        contador = 0
        for s, p, o in self.grafo:
            print("Sujeto:   ", s)
            print("Predicado:", p)
            print("Objeto:   ", o)
            print("--------------------------")
            contador += 1
            if contador == limite:
                break

    def recomendar_controles(self, amenaza_nombre):
        amenaza_uri = ns[amenaza_nombre]
        consulta = f"""
        SELECT ?control WHERE {{
            ?control <{ns.mitiga}> <{amenaza_uri}> .
        }}
        """
        resultados = [str(r[0]).split("#")[-1] for r in self.grafo.query(consulta)]
        return resultados if resultados else ["Sin controles registrados"]

    def activos_afectados(self, amenaza_nombre):
        amenaza_uri = ns[amenaza_nombre]
        consulta = f"""
        SELECT ?activo WHERE {{
            <{amenaza_uri}> <{ns.afecta}> ?activo .
        }}
        """
        resultados = [str(r[0]).split("#")[-1] for r in self.grafo.query(consulta)]
        return resultados if resultados else ["Sin activos afectados"]

    def nivel_riesgo(self, amenaza_nombre):
        amenaza_uri = ns[amenaza_nombre]
        consulta = f"""
        SELECT ?riesgo WHERE {{
            <{amenaza_uri}> <{ns.nivelRiesgo}> ?riesgo .
        }}
        """
        resultados = list(self.grafo.query(consulta))
        return str(resultados[0][0]) if resultados else "No definido"

    def listar_amenazas(self):
        consulta = f"""
        SELECT ?individuo WHERE {{
            ?individuo a ?clase .
            ?clase <http://www.w3.org/2000/01/rdf-schema#subClassOf> <{ns.Amenaza}> .
        }}
        """
        resultados = [str(r[0]).split("#")[-1] for r in self.grafo.query(consulta)]
        return resultados if resultados else ["Sin amenazas encontradas"]

    def diagnostico(self, amenaza_nombre):
        print(f"\n{'='*45}")
        print(f"  DIAGNÓSTICO: {amenaza_nombre}")
        print(f"{'='*45}")
        print(f"  Nivel de riesgo  : {self.nivel_riesgo(amenaza_nombre)}")
        print(f"  Activos afectados: {self.activos_afectados(amenaza_nombre)}")
        print(f"  Controles suger. : {self.recomendar_controles(amenaza_nombre)}")
        print(f"{'='*45}\n")

    def chatbot(self):
        print("\n" + "="*45)
        print("  AGENTE DE CIBERSEGURIDAD - CHATBOT")
        print("="*45)
        print("  Escribe 'salir' para terminar")
        print("  Escribe 'lista' para ver amenazas")
        print("="*45 + "\n")

        while True:
            entrada = input("Tu consulta: ").strip()

            if entrada.lower() == "salir":
                print("Cerrando agente...")
                break

            elif entrada.lower() == "lista":
                amenazas = self.listar_amenazas()
                print("\nAmenazas disponibles:")
                for a in amenazas:
                    print(f"  - {a}")
                print()

            else:
                amenazas = self.listar_amenazas()
                coincidencia = None

                for a in amenazas:
                    if entrada.lower() in a.lower():
                        coincidencia = a
                        break

                if coincidencia:
                    self.diagnostico(coincidencia)
                else:
                    print(f"\n  Amenaza '{entrada}' no encontrada.")
                    print("  Escribe 'lista' para ver las amenazas disponibles.\n")


agente = AgenteCiberseguridad(g)

agente.mostrar_relaciones(10)

agente.diagnostico("Phishing_Corporativo")
agente.diagnostico("Ransomware_WannaCry")

print("Amenazas detectadas:", agente.listar_amenazas())
print("Controles para Phishing:", agente.recomendar(ns.Phishing_Corporativo))

agente.chatbot()

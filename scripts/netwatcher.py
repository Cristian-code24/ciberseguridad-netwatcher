# -*- coding: utf-8 -*-
"""
NetWatcher GUI - Herramienta Educativa de Escaneo de Red

Este script lanza una interfaz gráfica de usuario (GUI) para realizar escaneos
de red de forma sencilla. Permite descubrir hosts mediante ARP y escanear
puertos básicos con Nmap.

Autor: Cristian-code24
Fecha: 2025-10-12
"""

import PySimpleGUI as sg
import threading
import os
import sys

# Añadir el directorio padre al path para poder importar utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.utils import (
    run_arp_scan,
    nmap_scan,
    export_csv,
    detect_local_cidr
)

# --- Constantes y Configuración ---
APP_TITLE = "NetWatcher - Escáner de Red Educativo"
TABLE_HEADINGS = ["IP", "MAC", "Hostname", "Vendor", "Puertos Abiertos"]
DEFAULT_THEME = "DarkBlue3"
LOG_LEVELS = {"INFO": "green", "WARN": "yellow", "ERROR": "red", "DEBUG": "lightblue"}

# --- Funciones de la GUI ---

def check_permissions():
    """Verifica si el script se ejecuta con privilegios de administrador."""
    if os.name == 'nt': # Sistema operativo Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    # Para Linux/macOS
    return os.geteuid() == 0

def log_message(window, message, level="INFO"):
    """Añade un mensaje al área de logs de la GUI con color."""
    color = LOG_LEVELS.get(level, "white")
    window["-LOG-"].print(f"[{level}] {message}", text_color=color)

def run_scan_thread(window, scan_function, *args):
    """
    Ejecuta una función de escaneo en un hilo separado para no bloquear la GUI.
    Actualiza la GUI con los resultados al finalizar.
    """
    try:
        results = scan_function(*args)
        window.write_event_value(("-SCAN-COMPLETE-", results), None)
    except Exception as e:
        window.write_event_value(("-SCAN-ERROR-", str(e)), None)

# --- Layout de la GUI ---

def create_main_window():
    """Crea y devuelve el objeto ventana principal de PySimpleGUI."""
    sg.theme(DEFAULT_THEME)

    controls_layout = [
        sg.Text("Rango de Red (CIDR):"),
        sg.Input(key="-CIDR-", size=(20, 1)),
        sg.Button("Detectar", key="-DETECT-"),
        sg.Button("Scan ARP", key="-ARP-SCAN-", button_color=("white", "green")),
        sg.Button("Nmap Quick Scan", key="-NMAP-SCAN-", disabled=True),
        sg.Button("Detener Scan", key="-STOP-", button_color=("white", "red"), disabled=True),
    ]

    table_layout = [
        sg.Table(
            values=[],
            headings=TABLE_HEADINGS,
            key="-RESULTS-",
            display_row_numbers=True,
            auto_size_columns=False,
            col_widths=[15, 15, 20, 20, 30],
            justification="left",
            enable_events=True,
            num_rows=15,
        )
    ]

    log_layout = [
        sg.Text("Logs y Notificaciones:"),
        sg.Multiline(
            key="-LOG-", size=(100, 8), autoscroll=True, disabled=True, reroute_stdout=False
        ),
        sg.Button("Exportar a CSV", key="-EXPORT-", disabled=True),
    ]

    layout = [
        [sg.Frame("Controles de Escaneo", [controls_layout])],
        [sg.Frame("Resultados", [table_layout])],
        [sg.Frame("Actividad", [log_layout])],
    ]

    return sg.Window(APP_TITLE, layout, finalize=True)


# --- Lógica Principal de la Aplicación ---

def main():
    """Bucle principal de eventos de la aplicación."""
    if not check_permissions():
        sg.popup_error(
            "Permisos Insuficientes",
            "El escaneo ARP requiere privilegios de Administrador.\n"
            "Por favor, cierra esta ventana y ejecuta el script desde una terminal de Administrador.",
        )

    window = create_main_window()
    scan_thread = None
    hosts_data = []

    while True:
        event, values = window.read()

        # Primero, verificamos si el evento es una tupla (como los de los hilos)
        if isinstance(event, tuple):
            event_key, event_data = event
        else:
            event_key = event
            event_data = None
        
        if event_key == sg.WIN_CLOSED:
            break

        if event_key == "-DETECT-":
            log_message(window, "Intentando detectar CIDR local...")
            cidr = detect_local_cidr()
            if cidr:
                window["-CIDR-"].update(cidr)
                log_message(window, f"CIDR detectado: {cidr}", "INFO")
            else:
                log_message(window, "No se pudo detectar el CIDR. Introdúcelo manualmente.", "WARN")

        elif event_key == "-ARP-SCAN-":
            if not check_permissions():
                log_message(window, "El escaneo ARP requiere privilegios de Administrador. Operación cancelada.", "ERROR")
                continue
            
            cidr_input = values["-CIDR-"]
            if not cidr_input:
                log_message(window, "Por favor, introduce un rango CIDR.", "ERROR")
                continue

            log_message(window, f"Iniciando escaneo ARP en {cidr_input}...")
            window["-ARP-SCAN-"].update(disabled=True)
            window["-STOP-"].update(disabled=False)
            
            hosts_data.clear()
            window["-RESULTS-"].update(values=[])
            window["-EXPORT-"].update(disabled=True)
            window["-NMAP-SCAN-"].update(disabled=True)

            scan_thread = threading.Thread(
                target=run_scan_thread, args=(window, run_arp_scan, cidr_input), daemon=True
            )
            scan_thread.start()

        elif event_key == "-SCAN-COMPLETE-":
            scan_results = event_data
            log_message(window, "Escaneo ARP completado.", "INFO")

            hosts_data = [
                [
                    host.get("ip", ""), host.get("mac", ""), host.get("hostname", "N/A"),
                    host.get("vendor", "N/A"), ""
                ]
                for host in scan_results
            ]
            window["-RESULTS-"].update(values=hosts_data)
            window["-EXPORT-"].update(disabled=False if hosts_data else True)
            
            window["-ARP-SCAN-"].update(disabled=False)
            window["-STOP-"].update(disabled=True)
            scan_thread = None

        elif event_key == "-SCAN-ERROR-":
            error_message = event_data
            log_message(window, f"Error durante el escaneo: {error_message}", "ERROR")
            window["-ARP-SCAN-"].update(disabled=False)
            window["-STOP-"].update(disabled=True)
            scan_thread = None

        elif event_key == "-RESULTS-":
            selected_rows = values["-RESULTS-"]
            window["-NMAP-SCAN-"].update(disabled=bool(selected_rows))
        
        elif event_key == "-NMAP-SCAN-":
            selected_rows = values["-RESULTS-"]
            if not selected_rows:
                log_message(window, "Selecciona un host de la tabla para escanear.", "WARN")
                continue
            
            selected_row_index = selected_rows[0]
            target_ip = hosts_data[selected_row_index][0]

            log_message(window, f"Iniciando Nmap Quick Scan en {target_ip}...")
            window["-NMAP-SCAN-"].update(disabled=True)
            
            def nmap_gui_thread(win, ip, row_index):
                try:
                    open_ports = nmap_scan(ip)
                    win.write_event_value(("-NMAP-COMPLETE-", (row_index, open_ports)), None)
                except Exception as e:
                    win.write_event_value(("-NMAP-ERROR-", str(e)), None)
            
            nmap_thread = threading.Thread(
                target=nmap_gui_thread, args=(window, target_ip, selected_row_index), daemon=True
            )
            nmap_thread.start()

        elif event_key == "-NMAP-COMPLETE-":
            # <<<--- CORRECCIÓN AQUÍ ---<<<
            # Desempacamos el contenido del paquete de datos
            row_index, open_ports = event_data
            log_message(window, f"Escaneo Nmap para {hosts_data[row_index][0]} completado.", "INFO")
            ports_str = ", ".join(map(str, open_ports)) if open_ports else "Ninguno"
            hosts_data[row_index][4] = ports_str
            window["-RESULTS-"].update(values=hosts_data)
            window["-NMAP-SCAN-"].update(disabled=False)

        elif event_key == "-NMAP-ERROR-":
            # <<<--- CORRECCIÓN AQUÍ ---<<<
            # Obtenemos el mensaje de error del paquete de datos
            error_message = event_data
            log_message(window, f"Error en Nmap: {error_message}", "ERROR")
            window["-NMAP-SCAN-"].update(disabled=False)
        
        elif event_key == "-EXPORT-":
            if not hosts_data:
                log_message(window, "No hay datos para exportar.", "WARN")
                continue

            filepath = sg.popup_get_file(
                "Guardar como", save_as=True, no_window=True, file_types=(("CSV Files", "*.csv"),)
            )
            if filepath:
                try:
                    export_data = [dict(zip(TABLE_HEADINGS, row)) for row in hosts_data]
                    export_csv(export_data, filepath)
                    log_message(window, f"Datos exportados a {filepath}", "INFO")
                except Exception as e:
                    log_message(window, f"Error al exportar: {e}", "ERROR")

    window.close()

if __name__ == "__main__":
    main()


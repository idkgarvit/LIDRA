import asyncio
from textual.app import App, ComposeResult
from textual.binding import Binding
from .screens.dashboard import DashboardScreen
from .screens.connections import ConnectionsScreen
from .screens.config import ConfigScreen
from .data_provider import TUIDataProvider

class LidraApp(App):
    CSS = """
    #main-row { height: 60%; }
    #bottom-row { height: 20%; }
    .panel-title { background: $primary; color: $text; padding: 0 1; }
    #dashboard-container { padding: 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("1", "switch_screen('dashboard')", "Dashboard", show=True),
        Binding("c", "switch_screen('connections')", "Connections", show=True),
        Binding("s", "switch_screen('config')", "Config", show=True),
        Binding("escape", "app.pop_screen", "Back", show=False),
    ]

    def __init__(self, data_provider: TUIDataProvider = None):
        super().__init__()
        self.data_provider = data_provider or TUIDataProvider()
        self.packet_history = [0] * 20

    def on_mount(self) -> None:
        self.install_screen(DashboardScreen(), name="dashboard")
        self.install_screen(ConnectionsScreen(), name="connections")
        self.install_screen(ConfigScreen(), name="config")
        self.push_screen("dashboard")
        self.run_worker(self.listen_to_events())

    async def listen_to_events(self):
        async for event in self.data_provider.subscribe():
            etype = event["type"]
            data = event["data"]
            
            if etype == "packet":
                self.packet_history.append(data["pkts_per_sec"])
                self.packet_history = self.packet_history[-20:]
            
            # Dispatch to dashboard if active
            if self.screen.name == "dashboard":
                self.screen.handle_event(etype, data)

if __name__ == "__main__":
    app = LidraApp()
    app.run()

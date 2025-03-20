# from gui.gui  import run_gui
#
# if __name__ == "__main__":
#     run_gui()

#!/usr/bin/env python

from gui.server_window import ServerWindow


def run_gui():
    """运行GUI"""
    app = ServerWindow()
    app.root.mainloop()


if __name__ == "__main__":
    run_gui()


from gui import ThemedTk, URLScannerGUI


if __name__ == '__main__':
    root = ThemedTk(theme="equilux")
    app = URLScannerGUI(root)
    root.mainloop()

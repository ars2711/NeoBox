
try:
    with open('static/styles.css', 'rb') as f:
        data = f.read()

    marker = b'[data-bs-theme="goofy"] .glass-navbar {'
    loc = data.find(marker)

    if loc != -1:
        new_content = data[:loc] + marker + b'''
  background-color: rgba(255, 200, 220, 0.85) !important;
  border-bottom: 3px dotted #ff00ff;
}

/* Fix for Tools Grid Layout */
#toolsGrid.row > * {
    margin-bottom: 1.5rem;
    padding-left: 0.75rem;
    padding-right: 0.75rem;
}
.tool-card {
    height: 100%;
    border-radius: 12px;
}
'''
        with open('static/styles.css', 'wb') as f:
            f.write(new_content)
        print("Successfully fixed styles.css")
    else:
        print("Marker not found in styles.css")
except Exception as e:
    print(f"Error: {e}")

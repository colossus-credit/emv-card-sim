#!/bin/bash
# Clear logs and wait for transaction

echo "Clearing all logs..."
java -jar gp.jar --applet A0000009510001 --apdu 80060100 > /dev/null 2>&1
java -jar gp.jar --applet A0000009511010 --apdu 80060100 > /dev/null 2>&1

echo ""
echo "✓ Logs cleared!"
echo ""
echo "╔════════════════════════════════════════╗"
echo "║  READY - Run your transaction NOW     ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "After transaction completes, immediately run:"
echo "  ./capture_transaction.sh"
echo ""

#!/bin/bash

echo "Installing Google GenAI SDK..."
pip install google-genai python-dotenv

echo "Creating .env file..."


cat > ~/.gcp/credentials <<EOL
[default]
GEMINI_STUDIO_API_KEY=$GEMINI_STUDIO_API_KEY
EOL

cat > ~/.gcp/config <<EOL
[default]
region=us-east-1
output=json
EOL

echo "Gemini setup complete."
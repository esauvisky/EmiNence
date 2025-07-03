# Eminence

A tool for analyzing strings in binary files to aid reverse engineering. It uses a machine learning model to score strings based on their potential relevance, helping to separate useful information from noise.

## Features

- **String Extraction**: Extracts printable strings from ELF binary files.
- **ML-Powered Scoring**: Uses an XGBoost model to assign a "meaningfulness" score to each string.
- **Interactive Training**: A simple GUI allows you to label strings as meaningful or not, and retrain the model on the fly to adapt to your specific target.
- **Training Mode**: An intelligent sampling mode to help you find and label the most impactful strings to improve the model.
- **GPU Acceleration**: Supports optional GPU acceleration for faster model training and prediction if a compatible GPU and drivers are present.
- **Session Management**: Save and load trained models and your labeled strings to resume work later.
- **AI-Assisted Labeling**: Integrate with the Google Gemini API to automatically label large batches of strings.
- **Command-Line Interface**: Load a binary, model, and labels directly from the command line for a faster workflow.

## Usage

Run the application and open a binary file to begin.

```
python eminence.py [path_to_binary]
```

Optional arguments:
- `--model <path_to_model.pkl>`: Load a previously saved model.
- `--labels <path_to_labels.json>`: Load previously saved labels.

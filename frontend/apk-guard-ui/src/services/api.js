const API_BASE_URL = 'http://localhost:8000';

export async function analyzeApk(file) {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE_URL}/analyze-apk`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || 'Failed to analyze APK file.');
  }

  return await response.json();
}
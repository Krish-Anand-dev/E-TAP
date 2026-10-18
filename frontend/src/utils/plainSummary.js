const summaries = {
  en: { danger:'Strong risk indicators were found. Verify through an official channel and avoid interacting with the message.', caution:'The available evidence is uncertain or suspicious. Ask for review before acting.', safe:'No high-risk evidence was found in the inspected material. Missing checks and false negatives remain possible.' },
  es: { danger:'Se encontraron indicadores de riesgo importantes. Verifica por un canal oficial y evita interactuar con el mensaje.', caution:'La evidencia disponible es incierta o sospechosa. Solicita una revisión antes de actuar.', safe:'No se encontraron indicios de alto riesgo en el material examinado. Puede haber comprobaciones faltantes y falsos negativos.' },
  hi: { danger:'गंभीर जोखिम के संकेत मिले हैं। आधिकारिक माध्यम से पुष्टि करें और संदेश से आगे संपर्क न करें।', caution:'उपलब्ध साक्ष्य अनिश्चित या संदिग्ध हैं। कार्रवाई से पहले समीक्षा कराएँ।', safe:'जाँची गई सामग्री में उच्च जोखिम के साक्ष्य नहीं मिले। कुछ जाँचें अधूरी हो सकती हैं और खतरे छूट सकते हैं।' },
};
export function plainSummary(band, language) { return (summaries[language] || summaries.en)[band] || summaries.en.caution; }

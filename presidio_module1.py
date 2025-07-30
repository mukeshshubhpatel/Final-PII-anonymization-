import spacy
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer import PatternRecognizer, RecognizerResult
from presidio_analyzer import PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
import regex as re

# Global variables for reuse
nlp = None
analyzer = None
anonymizer = None
address_recognizer = None
zip_recognizer = None
hipaa_zip_recognizer = None
age_recognizer = None
custom_id_recognizer = None

def initialize_nlp_components():
    """Initialize NLP components once instead of on each function call"""
    global nlp, analyzer, anonymizer, address_recognizer, zip_recognizer, hipaa_zip_recognizer, age_recognizer, custom_id_recognizer
    
    nlp = spacy.load("en_core_web_sm", disable=["ner"]) # Disable NER if not needed for performance
    analyzer = AnalyzerEngine()
    anonymizer = AnonymizerEngine()

    # Register custom recognizers
    # Address recognizer
    address_recognizer = PatternRecognizer(
        supported_entity="ADDRESS",
        patterns=[
            Pattern(
                name="address_pattern",
                regex=r"\b\d{1,5}\s\w+(?:\s\w+)*\s(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Square|Sq|Plaza|Plz|Trail|Trl|Terrace|Ter|Place|Pl|Parkway|Pkwy|Loop)\b",
                score=0.85
            ),
            Pattern(
                name="address_with_city",
                regex=r"\b\d{1,5}\s\w+(?:\s\w+)*,\s?\w+(?:\s\w+)*(?:,\s?[A-Za-z]{2}\s?\d{5})?\b",
                score=0.85
            ),
            Pattern(
                name="address_with_zip",
                regex=r"\b\d{1,5}\s[\w\s]+,\s*\w+\s*,\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?\b",
                score=0.9
            ),
            Pattern(
                name="po_box",
                regex=r"\bP\.?O\.?\s*Box\s+\d+\b",
                score=0.85
            ),
        ]
    )
    
    # Date recognizer (needed for proper date detection)
    date_recognizer = PatternRecognizer(
        supported_entity="DATE",
        patterns=[
            Pattern(
                name="date_mmddyyyy",
                regex=r"\b(0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12]\d|3[01])[\/\-](19|20)?\d{2}\b",
                score=0.85
            ),
            Pattern(
                name="date_month_dd_yyyy",
                regex=r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+(?:0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?,?\s+(?:19|20)?\d{2}\b",
                score=0.85
            ),
            Pattern(
                name="date_dd_month_yyyy",
                regex=r"\b(?:0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+(?:19|20)?\d{2}\b",
                score=0.85
            ),
            Pattern(
                name="date_yyyy_mm_dd",
                regex=r"\b(?:19|20)?\d{2}[\/\-](0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12]\d|3[01])\b",
                score=0.85
            ),
        ]
    )

    # ZIP Code recognizer
    zip_recognizer = PatternRecognizer(
        supported_entity="ZIP_CODE",
        patterns=[
            Pattern(
                name="zip_5_digit",
                regex=r"\b\d{5}(?!\d)",  # 5 digits not followed by another digit
                score=0.8
            ),
            Pattern(
                name="zip_9_digit",
                regex=r"\b\d{5}-\d{4}\b",  # ZIP+4 format
                score=0.9
            ),
        ]
    )
        # ✅ Add HIPAA age recognizer for 90+
    age_recognizer = PatternRecognizer(
    supported_entity="HIPAA_AGE",
    patterns=[
        Pattern("age_phrase", r"\bage\s+(?:9[0-9]|[1-9][0-9]{2,})\b", 0.9),
        Pattern("year_phrase", r"\b(?:9[0-9]|[1-9][0-9]{2,})[- ]?(year(?:s)?|yr|yrs)[- ]?(old)?\b", 0.9),
        Pattern("phrase_90_year_old", r"\b(?:age\\s+)?(?:9[0-9]|[1-9][0-9]{2,})\\s+year[s]?\\s+old\\b", 0.9)
    ]
)

    analyzer.registry.add_recognizer(age_recognizer)
    # HIPAA ZIP recognizer (first 3 digits only for population < 20,000)
    hipaa_zip_recognizer = PatternRecognizer(
        supported_entity="HIPAA_ZIP",
        patterns=[
            Pattern(
                name="hipaa_zip_pattern",
                regex=r"\b\d{3}00\b",  # Pattern for HIPAA compliant ZIP (e.g., 12300)
                score=0.8
            ),
        ]
    )

    # Age recognizer for HIPAA compliance (90+ years)
    age_recognizer = PatternRecognizer(
        supported_entity="HIPAA_AGE",
        patterns=[
            Pattern(
                name="age_90_plus",
                regex=r"\b(?:9[0-9]|[1-9][0-9]{2,})-year-old\b",  # 90+ year old
                score=0.9
            ),
            Pattern(
                name="age_90_plus_simple",
                regex=r"\bage\s+(?:9[0-9]|[1-9][0-9]{2,})\b",  # age 90+
                score=0.9
            ),
            Pattern(
                name="age_90_plus_years",
                regex=r"\b(?:9[0-9]|[1-9][0-9]{2,})\s+years?\s+old\b",  # 90+ years old
                score=0.9
            ),
        ]
    )

    # VERY SPECIFIC Custom ID recognizer - only matches exact formats
    custom_id_recognizer = PatternRecognizer(
        supported_entity="CUSTOM_ID",
        patterns=[
            # ONLY Patient ID with specific format
            Pattern(
                name="patient_id_exact",
                regex=r'\bPatient\s+ID\s+[A-Z]\d{6}\b',
                score=0.95
            ),
            # ONLY specific asterisk patterns
            Pattern(
                name="id_asterisk_exact",
                regex=r'\b(?:ID|MR)\d{6}\*{5,}\b',
                score=0.95
            ),
            # ONLY numbers with asterisks
            Pattern(
                name="numbers_asterisk_exact",
                regex=r'\b\d{5}\*{5,}\b',
                score=0.95
            ),
            # ONLY very specific letter-number patterns
            Pattern(
                name="exact_letter_number_pattern",
                regex=r'\b[A-Z]{2}\d{6}[A-Z]{2}\b',
                score=0.9
            ),
            # ONLY specific mixed patterns like 12AB345CD
            Pattern(
                name="exact_mixed_pattern",  
                regex=r'\b\d{2}[A-Z]{2}\d{3}[A-Z]{2}\b',
                score=0.9
            ),
        ]
    )

    analyzer.registry.add_recognizer(address_recognizer)
    analyzer.registry.add_recognizer(date_recognizer)
    analyzer.registry.add_recognizer(zip_recognizer)
    analyzer.registry.add_recognizer(hipaa_zip_recognizer)
    analyzer.registry.add_recognizer(age_recognizer)
    analyzer.registry.add_recognizer(custom_id_recognizer)

# Cache for medical entities to avoid repeat processing
medical_entities_cache = {}

def extract_drugs_and_medical_terms(raw_data):
    # Check cache first
    if raw_data in medical_entities_cache:
        return medical_entities_cache[raw_data]
    
    global nlp
    if nlp is None:
        initialize_nlp_components()
        
    doc = nlp(raw_data)
    recognized_entities = []
    for ent in doc.ents:
        if ent.label_ in ["DISEASE", "DRUG", "MEDICAL_TERM"]:
            recognized_entities.append(ent.text)
    
    result = set(recognized_entities)
    # Store in cache
    medical_entities_cache[raw_data] = result
    return result

def anonymize_with_presidio_selective_batch(raw_data, options):
    """Process the entire text at once with very specific ID patterns"""
    global analyzer, anonymizer
    if analyzer is None or anonymizer is None:
        initialize_nlp_components()
    
    final_text = raw_data
    medical_entities = extract_drugs_and_medical_terms(raw_data)
    
    # Step 1: Handle specific ID patterns with regex FIRST (most precise)
    if options.get('id', False):
        # Very specific patterns only
        id_patterns = [
            (r'\bPatient\s+ID\s+[A-Za-z]\d{6}\b', '<span class="id-anonymized">[ID_Anonymized]</span>'),
            (r'\b(?:ID|MR)\d{6}\*{5,}\b', '<span class="id-anonymized">[ID_Anonymized]</span>'),
            (r'\b\d{5}\*{5,}\b', '<span class="id-anonymized">[ID_Anonymized]</span>'),
            (r'\b[A-Z]{2}\d{6}[A-Z]{2}\b', '<span class="id-anonymized">[ID_Anonymized]</span>'),
            (r'\b\d{2}[A-Z]{2}\d{3}[A-Z]{2}\b', '<span class="id-anonymized">[ID_Anonymized]</span>'),
            (r'\b[A-Z]\d{7}\b', '<span class="id-anonymized">[ID_Anonymized]</span>'),
            (r'\b[A-Z]{2}\d{5}\b', '<span class="id-anonymized">[ID_Anonymized]</span>'),
            (r'\b[A-Z]\d{6}\b', '<span class="id-anonymized">[ID_Anonymized]</span>'),
            (r'\b[A-Za-z]\d{5,7}\b', '<span class="id-anonymized">[ID_Anonymized]</span>'),
            (r'\b[A-Za-z]\d{4,6}[A-Za-z]\d{1,2}\b', '<span class="id-anonymized">[ID_Anonymized]</span>'),
            (r'\b(?=(?:[A-Za-z]*\d){2,})(?=(?:\d*[A-Za-z]){2,})[A-Za-z0-9]{6,12}\b', '<span class="id-anonymized">[ID_Anonymized]</span>'),
            (r'\b(?=[A-Za-z]*\d)(?=\d*[A-Za-z])[A-Za-z0-9]{6,12}\b', '<span class="id-anonymized">[ID_Anonymized]</span>')


        ]
        
        for pattern, replacement in id_patterns:
            # Only replace if not part of medical terms
            matches = list(re.finditer(pattern, final_text))
            for match in reversed(matches):  # Process in reverse to maintain positions
                matched_text = match.group()
                if matched_text.lower() not in [term.lower() for term in medical_entities]:
                    final_text = final_text[:match.start()] + replacement + final_text[match.end():]
    
    # Step 2: Handle other entities with Presidio
    entities = []
    if options.get('date', False):
        entities.append("DATE")
    if options.get('name', False):
        entities.append("PERSON") 
    if options.get('email', False):
        entities.append("EMAIL_ADDRESS")
    if options.get('phone', False):
        entities.append("PHONE_NUMBER")
    if options.get('zip', False):
        entities.append("ZIP_CODE")
    if options.get('address', False):
        entities.append("ADDRESS")
    if options.get('hipaa_age', False):
        entities.append("HIPAA_AGE")

    if entities:
        try:
            analysis_results = analyzer.analyze(
                text=final_text,
                language="en",
                entities=entities
            )
            
            if analysis_results:
                # Configure operators with HTML spans
                anonymization_config = {}
                if options.get('date', False):
                    anonymization_config["DATE"] = OperatorConfig("replace", {"new_value": "<span class='date-anonymized'>[Date_Anonymized]</span>"})
                if options.get('name', False):
                    anonymization_config["PERSON"] = OperatorConfig("replace", {"new_value": "<span class='name-anonymized'>[Name_Anonymized]</span>"})
                if options.get('email', False):
                    anonymization_config["EMAIL_ADDRESS"] = OperatorConfig("replace", {"new_value": "<span class='email-anonymized'>[Email_Anonymized]</span>"})
                if options.get('phone', False):
                    anonymization_config["PHONE_NUMBER"] = OperatorConfig("replace", {"new_value": "<span class='phone-anonymized'>[Phone_Anonymized]</span>"})
                if options.get('address', False):
                    anonymization_config["ADDRESS"] = OperatorConfig("replace", {"new_value": "<span class='address-anonymized'>[Address_Anonymized]</span>"})
                if options.get('zip', False):
                    anonymization_config["ZIP_CODE"] = OperatorConfig("replace", {"new_value": "<span class='zip-anonymized'>[ZIP_Anonymized]</span>"})
                if options.get('hipaa_zip', False):
                    anonymization_config["HIPAA_ZIP"] = OperatorConfig("replace", {"new_value": "<span class='hipaa-zip-anonymized'>[HIPAA_ZIP_Anonymized]</span>"})
                if options.get('hipaa_age', False):
                    anonymization_config["HIPAA_AGE"] = OperatorConfig("replace", {"new_value": "<span class='age-anonymized'>90+</span>"})
                
                # Sort by position (reverse order)
                analysis_results.sort(key=lambda x: x.start, reverse=True)
                
                anonymized_result = anonymizer.anonymize(
                    text=final_text,
                    analyzer_results=analysis_results,
                    operators=anonymization_config
                )
                final_text = anonymized_result.text
                
        except Exception as e:
            print(f"Error in Presidio anonymization: {e}")

    return final_text

# Backward compatibility function
def anonymize_with_presidio_selective(raw_data, options):
    return anonymize_with_presidio_selective_batch(raw_data, options)
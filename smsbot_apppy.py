@app.route('/analyze-text', methods=['POST'])
def analyze_text():
    data    = request.json
    content = data.get('content', '')

    # NLP Layer
    nlp_verdict, nlp_score, nlp_reason = analyze_text_with_ai(content)

    # Technical URL Layer
    urls        = extract_urls(content)
    url_results = []

    for url in urls:
        domain   = url.split("//")[-1].split("/")[0]
        is_https = url.lower().startswith("https://")

        if not is_https:
            prob    = 60
            verdict = "Suspicious"
            url_results.append({"url": url, "domain": domain,
                                 "probability_score": prob, "verdict": verdict})
            continue

        if any(w_domain in domain.lower() for w_domain in WHITELIST):
            prob    = 0
            verdict = "Safe"
        else:
            age       = get_domain_age(domain)
            ssl_valid = check_ssl(domain)
            prob      = calculate_url_probability(age, ssl_valid)
            verdict   = "Suspicious" if prob > 40 else "Safe"

        url_results.append({"url": url, "domain": domain,
                             "probability_score": prob, "verdict": verdict})

    return jsonify({
        "nlp":  {"verdict": nlp_verdict, "score": nlp_score, "reason": nlp_reason},
        "urls": url_results
    })

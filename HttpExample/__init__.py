import logging
import json

import azure.functions as func


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    req_body = req.get_json()

    # Read Input JSOn
    threat = req_body["threat"]
    year = req_body["analysisYear"]
    parameters = req_body["parameters"]
    attributes = req_body["attributes"]

    print(attributes)

    formatted_input_json = {
        "threat" : threat,
        "analysisYear" : year,
        "attributes" : format_attribute_for_input(attributes),
        "parameters" : format_attribute_for_input(parameters),
        "failureScenarios" : [],
        "frequencies" : []
        }


    if attributes:
        return func.HttpResponse(json.dumps(formatted_input_json))
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             status_code=200
        )

def format_input(attribute):
    formatted_attr = {}

    for x in attribute:
        code = x['code']
        value = x['value']

        formatted_attr[code] = value

    return json.dumps(formatted_attr)

def format_attribute_for_input(input_json):
    attr_pairs = []

    for x,y in input_json.items():
        pair = {
            "code": x,
            "value": y
        }
        attr_pairs.append(pair)
    return attr_pairs
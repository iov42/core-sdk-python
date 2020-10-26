"""Create example test data."""
import csv
import random
import string
import uuid

if __name__ == "__main__":
    generated_data = []
    for _ in range(100):
        product = random.choice(string.ascii_uppercase)  # noqa: S311
        serial_no = uuid.uuid4()
        generated_data.append(
            (
                uuid.uuid4(),
                f"producer: new-corp|product: {product}|serial_no: {serial_no}",
            )
        )
    with open("nfc-tags.csv", "wt") as fp:
        writer = csv.writer(fp, delimiter=";")
        writer.writerow(["NFC serial", "product info"])
        writer.writerows(generated_data)

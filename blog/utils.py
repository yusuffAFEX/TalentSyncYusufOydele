import random

from django.utils.text import slugify


def generate_slug(title, more=False):
    slug = slugify(title)
    if more:
        random_number = '{:02d}'.format(random.randrange(1, 99))
        slug = f'{title}{random_number}'
    return slug.lower().replace(" ", "-")

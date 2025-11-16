from django import forms


METHOD_CHOICES = [
    ('GET', 'GET'),
    ('POST', 'POST'),
    ('PUT', 'PUT'),
    ('DELETE', 'DELETE'),
]


class ScanForm(forms.Form):
    target_url = forms.URLField(label='Target URL', initial='http://ctf.ziinhh.org/login/')
    default_params = forms.CharField(
        label='Default params (JSON)',
        widget=forms.Textarea(attrs={'rows': 4}),
        initial='{"next": "/"}',
        help_text='Provide JSON object for default params, e.g. {"next":"/"}'
    )
    request_method = forms.ChoiceField(label='Method', choices=METHOD_CHOICES, initial='POST')
    cookies = forms.CharField(
        label='Cookies (JSON)',
        required=False,
        widget=forms.Textarea(attrs={'rows': 3}),
        help_text='Optional cookies as JSON, e.g. {"PHPSESSID":"..."}'
    )
    headers = forms.CharField(
        label='Headers (JSON)',
        required=False,
        widget=forms.Textarea(attrs={'rows': 3}),
        help_text='Optional headers as JSON'
    )
    do_dump = forms.BooleanField(label='Do dump (enumerate DB)', required=False, initial=False)

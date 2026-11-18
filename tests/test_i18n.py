"""Юнит-тесты локализации (nginxparse/i18n.py)."""

import unittest

from nginxparse import i18n
from nginxparse.i18n import detect_lang, get_lang, lang_from_locale, plural_word, set_lang, t


class LocaleDetectTest(unittest.TestCase):
    def test_lc_all_c_is_english(self):
        self.assertEqual(detect_lang({'LC_ALL': 'C'}), 'en')

    def test_lc_all_ru_is_russian(self):
        self.assertEqual(detect_lang({'LC_ALL': 'ru_RU'}), 'ru')
        self.assertEqual(detect_lang({'LC_ALL': 'ru_RU.UTF-8'}), 'ru')

    def test_english_locale(self):
        self.assertEqual(detect_lang({'LANG': 'en_US.UTF-8'}), 'en')

    def test_posix_and_c_utf8_are_english(self):
        self.assertEqual(detect_lang({'LC_ALL': 'POSIX'}), 'en')
        self.assertEqual(detect_lang({'LANG': 'C.UTF-8'}), 'en')

    def test_lc_all_wins_over_lang(self):
        env = {'LC_ALL': 'C', 'LANG': 'ru_RU.UTF-8'}
        self.assertEqual(detect_lang(env), 'en')
        env = {'LC_ALL': 'ru_RU.UTF-8', 'LANG': 'en_US.UTF-8'}
        self.assertEqual(detect_lang(env), 'ru')

    def test_empty_lc_all_falls_through(self):
        env = {'LC_ALL': '', 'LC_MESSAGES': '', 'LANG': 'ru_RU.UTF-8'}
        self.assertEqual(detect_lang(env), 'ru')

    def test_no_locale_defaults_to_english(self):
        self.assertEqual(detect_lang({}), 'en')

    def test_unknown_locale_defaults_to_english(self):
        self.assertEqual(detect_lang({'LANG': 'de_DE.UTF-8'}), 'en')

    def test_language_list(self):
        self.assertEqual(lang_from_locale('ru_RU:en_US'), 'ru')
        self.assertEqual(lang_from_locale('en_US:ru_RU'), 'en')


class TranslateTest(unittest.TestCase):
    def setUp(self):
        self._saved = get_lang()

    def tearDown(self):
        set_lang(self._saved)

    def test_russian(self):
        set_lang('ru')
        self.assertEqual(t('data.none'), 'Нет данных.')
        self.assertEqual(t('report.ip', net='203.0.0.0'), 'IP: 203.0.0.0')
        self.assertEqual(t('cli.found', n=3), 'Найдено логов: 3')

    def test_english(self):
        set_lang('en')
        self.assertEqual(t('data.none'), 'No data.')
        self.assertEqual(t('report.ip', net='203.0.0.0'), 'IP: 203.0.0.0')
        self.assertEqual(t('cli.found', n=3), 'Logs found: 3')

    def test_plural_russian(self):
        set_lang('ru')
        self.assertEqual(plural_word(1, 'request'), 'запрос')
        self.assertEqual(plural_word(2, 'request'), 'запроса')
        self.assertEqual(plural_word(5, 'request'), 'запросов')
        self.assertEqual(plural_word(21, 'request'), 'запрос')

    def test_plural_english(self):
        set_lang('en')
        self.assertEqual(plural_word(1, 'request'), 'request')
        self.assertEqual(plural_word(2, 'request'), 'requests')
        self.assertEqual(plural_word(0, 'request'), 'requests')

    def test_all_catalogs_have_same_keys(self):
        ru_keys = set(i18n._RU)
        en_keys = set(i18n._EN)
        self.assertEqual(ru_keys, en_keys)

    def test_no_em_dash_in_catalogs(self):
        for lang, catalog in i18n._CATALOG.items():
            for key, value in catalog.items():
                if key == 'plural':
                    continue
                self.assertNotIn('—', value, msg=f'{lang}:{key}')

    def test_unknown_key_falls_back_to_itself(self):
        set_lang('en')
        self.assertEqual(t('no.such.key'), 'no.such.key')


if __name__ == '__main__':
    unittest.main()

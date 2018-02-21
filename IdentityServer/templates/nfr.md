| Numer      | Status | Treść wymagania           | Komentarz  |
| :---: | :---: |---| -----|
|1|❔| Proces budowania i deploymentu jest w pełni automatyczny w oparciu o TeamCity, Octopus i nie wymaga ręcznych akcji ani nie wymaga dostępu (np. logowanie się poprzez RDP czy ssh) do środowiska produkcyjnego. Proces ten może być uruchomiony przez każdego Frontend developera.| budowanie jest lokalne, dla potrzeb ansiblea |
|2|❔| Aplikacja na produkcji posiada zminifikowany kod JS i CSS. | ok? |
|3|❔| Odświeżenie pamięci podręcznej z kodem JS i CSS w przeglądarce użytkownika odbywa się automatycznie po wydaniu nowszej wersji np. poprzez odpowiedni zestaw nagłówków, wersjonowanie nazwy plików. | ok? |
|4|❔| Wszystkie środowiska produkcyjne i beta aplikacji webowej są dostępne wyłącznie przez https. | mogloby byc, .gp.local |
|5|❔| W kodzie wynikowym dostępnym dla użytkownika (CSS, JS, HTML) nie przechowujemy informacji o architekturze naszego środowiska (np. lokalne i testowe adresy url) i nie wypisujemy żadnych informacji do konsoli deweloperskiej (np. korzystając z console.log). | ok? |
|6|❔| W repozytorium, w pliku README, znajduje się lista wspieranych przeglądarek wraz z ich minimalnymi wersjami. | trzeba dodac |
|7|❔| W repozytorium git znajduje się opis procesu instalacji i uruchomienia aplikacji front-end.| de facto front nie ma tu niczego wlasnego? |
|8|❔| Nie przechowujemy po stronie klienta żadnych danych uwierzytelniających oprócz access token.| ok |
|9|❔| Kod TS, JS, CSS jest analizowany statycznie przez SonarQube. | nie, i chyba nie będzie? |
|10|❔| Projekt posiada zdefiniowany style guide, który jest sprawdzany automatycznie za pomocą odpowiedniego narzędzia np. tslint, eslint, csslint.| nie |
|11|❔|Projekt "nie buduje się" w TeamCity jeżeli kod nie spełnia kryteriów określonych w style guide lub nie spełnia wymagań określonych w testach jednostkowych.| nie dotyczy? |

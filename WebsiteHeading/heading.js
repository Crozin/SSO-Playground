// Nie bijce, nie znam JS

(function (w) {
    "use strict";

    w.gp = w.gp || {};
    w.gp.heading = (function () {
        var d = w.document;
        var config = JSON.parse(d.getElementById(d.currentScript.dataset["config"]).innerText.trim());
        var target = d.querySelector(config.target);

        var render = function() {
            while (target.lastChild !== null) {
                target.removeChild(target.lastChild);
            }

            var userHeadingMarkup = "Witaj! <a href='" + config.signinUri + "' id='gp-heading-signin'>zaloguj się</a>";

            if (this.config.id_token !== null) {
                // TODO dodać opecję parsowania jwt id token i automatycznego wypełnienia this.user
            }

            if (this.config.user !== null) {
                userHeadingMarkup =
                    "Witaj <b>" + this.config.user.name + "</b>! " +
                    "<a href='" + this.config.signoutUri + "' id='gp-heading-signout'>wyloguj się</a>";
            }

            const headingMarkup =
                "<div class='container'>" +
                    "<div class='pull-right'>" +
                        userHeadingMarkup +
                    "</div>" +
                    "Basic <abbr title='Signle Sign-On'>SSO</abbr>: " +
                    "<a href='http://website1.sso/'>#1</a>, <a href='http://website2.sso/'>#2</a>, " +
                    "<a href='http://website3.sso/'>#3</a>, <a href='http://website4.sso/'>#4</a>, " +
                    "<a href='http://website5.sso/'>#5</a>, <a href='http://website6.sso/'>#6</a>" +
                    " &mdash; " +
                    "<abbr title='Frontchannel Single Sign-On'>FCSSO</abbr>: " +
                    "<a href='http://website-a.shared.sso.com/'>A</a> | " +
                    "<a href='http://website-b.shared.sso.com/'>B</a>" +
                    " &mdash; " +
                    "<abbr title='Stackoverflow'>SO</abbr>-like <abbr title='Universal Sign-On'>USO</abbr>: " +
                    "<a href='http://website-pracuj.sso/'>Oferty</a> | " +
                    "<a href='http://website-cv.sso/'>CV</a> | " +
                    "<a href='http://website-pracodawcy.sso/'>Pracodawcy</a>" +
                "</div>";

            target.insertAdjacentHTML("afterbegin", headingMarkup);
        };

        return {
            config: config,
            render: render
        };
    })();

    w.gp.heading.render();
})(this);
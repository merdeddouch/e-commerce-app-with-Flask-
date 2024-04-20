document.addEventListener('DOMContentLoaded', function () {
    const searchInput = document.getElementById('search');
    const productCards = document.querySelectorAll('.col');
    const category = {'1':"food",'2':"tech",'3':"school",'4':"clothes",'5':"beauty"};

    searchInput.addEventListener('input', filterProducts);

    function filterProducts() {
      const searchValue = searchInput.value.toLowerCase();

      productCards.forEach(function (card) {
        const productName = card.querySelector('.products_name').textContent.toLowerCase();
        const productId = card.classList[1];


        const productCategory = category[productId] || '';

        if (productName.includes(searchValue) || productCategory.toLowerCase() === searchValue) {
          card.style.display = 'block';
        } else {
          card.style.display = 'none';
        }
      });
    }
  });

  const rangeInput = document.getElementById('range');
  const bonusCashElement = document.getElementById('valBonusBill');
  const valeMax = document.getElementById('valMax');

  const billtot = document.getElementById('tot');
  const billtot_hidden = document.getElementById('hidden_tot');
  const initBill = document.getElementById('initBill').textContent;
  console.log(initBill);
  console.log(billtot.textContent);
  rangeInput.value = 0;

  rangeInput.addEventListener("input", () => {
  const rangeValue = parseFloat(rangeInput.value);
  bonusCashElement.textContent = rangeValue.toFixed(2) + ' DH';
  const facture_TTC =billtot.textContent = initBill - rangeValue.toFixed(2);
  console.log(facture_TTC);
  billtot.innertext = facture_TT.CtoFixed(2);
  billtot_hidden.innertext = facture_TTC.toFixed(2);
  });


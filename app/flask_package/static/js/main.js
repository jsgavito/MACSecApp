const btnDelete = document.querySelectorAll('.btn-delete')

if(btnDelete) {
    const btnArray=Array.from(btnDelete);
    btnArray.forEach((btn) => {
        btn.addEventListener('click', (e) => {
           if(!confirm('Confirm Deletion')) {
            e.preventDefault();   
           }
        });
    });
}

elements = document.getElementsByTagName("td")
for (var i = elements.length; i--;) {
  if (elements[i].innerHTML === "disabled") {
    elements[i].style.color = "red";
  }
  if (elements[i].innerHTML === "enabled") {
    elements[i].style.color = "green";
  }
}